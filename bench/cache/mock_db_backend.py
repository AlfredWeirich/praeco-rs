#!/usr/bin/env python3
"""Zero-dependency HTTP/1.1 Keep-Alive + SQLite mock DB backend for cache benchmarks."""

import argparse
import asyncio
import json
import sqlite3
import urllib.parse


CATEGORIES = ("fruit", "bakery", "dairy", "drinks", "snacks")


def init_db(num_rows: int) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        """
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            category TEXT NOT NULL,
            sku TEXT NOT NULL,
            name TEXT NOT NULL,
            price_cents INTEGER NOT NULL,
            stock INTEGER NOT NULL,
            description TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX idx_products_cat_price ON products (category, price_cents DESC)")
    rows = [
        (
            i,
            CATEGORIES[i % len(CATEGORIES)],
            f"SKU-{i:05d}",
            f"Sample {CATEGORIES[i % len(CATEGORIES)].title()} Item #{i}",
            150 + ((i * 73) % 4500),
            (i * 17) % 250,
            f"Fresh catalog product #{i} for gateway caching and JSON compression benchmark.",
        )
        for i in range(1, num_rows + 1)
    ]
    conn.executemany("INSERT INTO products VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
    conn.commit()
    return conn


class MockDbApp:
    def __init__(self, conn: sqlite3.Connection, db_delay_ms: float, num_rows: int) -> None:
        self.conn = conn
        self.db_delay_secs = max(0.0, db_delay_ms / 1000.0)
        self.db_delay_ms = db_delay_ms
        self.num_rows = num_rows
        self.db_queries = 0
        self.db_writes = 0

    def query_products(self, category: str, limit: int) -> bytes:
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT id, category, sku, name, price_cents, stock, description
            FROM products
            WHERE category = ?
            ORDER BY price_cents DESC
            LIMIT ?
            """,
            (category, limit),
        )
        items = [
            {
                "id": r[0],
                "category": r[1],
                "sku": r[2],
                "name": r[3],
                "price_cents": r[4],
                "stock": r[5],
                "description": r[6],
            }
            for r in cur.fetchall()
        ]
        agg = cur.execute(
            "SELECT COUNT(*), COALESCE(ROUND(AVG(price_cents), 2), 0) FROM products WHERE category = ?",
            (category,),
        ).fetchone()
        payload = {
            "category": category,
            "total_matching": agg[0],
            "avg_price_cents": agg[1],
            "items": items,
        }
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    async def handle_request(
        self, method: str, target: str, body: bytes
    ) -> tuple[int, str, bytes, str]:
        parsed = urllib.parse.urlsplit(target)
        path = parsed.path

        if method == "GET" and path == "/api/products":
            qs = urllib.parse.parse_qs(parsed.query)
            category = qs.get("category", ["fruit"])[0]
            try:
                limit = max(1, min(100, int(qs.get("limit", ["25"])[0])))
            except ValueError:
                limit = 25
            self.db_queries += 1
            if self.db_delay_secs > 0:
                await asyncio.sleep(self.db_delay_secs)
            data = self.query_products(category, limit)
            return 200, "OK", data, "public, max-age=60"

        if method == "POST" and path == "/api/query":
            category = "fruit"
            limit = 25
            if body:
                try:
                    req_json = json.loads(body.decode("utf-8"))
                    category = str(req_json.get("category", "fruit"))
                    limit = max(1, min(100, int(req_json.get("limit", 25))))
                except (ValueError, TypeError, UnicodeDecodeError):
                    pass
            self.db_queries += 1
            if self.db_delay_secs > 0:
                await asyncio.sleep(self.db_delay_secs)
            data = self.query_products(category, limit)
            return 200, "OK", data, "public, max-age=60"

        if method == "POST" and path == "/api/mutate":
            self.db_writes += 1
            if self.db_delay_secs > 0:
                await asyncio.sleep(self.db_delay_secs)
            self.conn.execute("UPDATE products SET stock = stock + 1 WHERE id = 1")
            self.conn.commit()
            data = json.dumps({"updated": True, "writes": self.db_writes}).encode("utf-8")
            return 200, "OK", data, "no-store"

        if method == "GET" and path == "/__stats":
            data = json.dumps(
                {
                    "db_queries": self.db_queries,
                    "db_writes": self.db_writes,
                    "db_delay_ms": self.db_delay_ms,
                    "rows": self.num_rows,
                }
            ).encode("utf-8")
            return 200, "OK", data, "no-store"

        if method == "POST" and path == "/__reset":
            self.db_queries = 0
            self.db_writes = 0
            return 200, "OK", b'{"ok":true}', "no-store"

        return 404, "Not Found", b'{"error":"not_found"}', "no-store"

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                raw_head = await reader.readuntil(b"\r\n\r\n")
                head_text = raw_head[:-4].decode("latin-1")
                lines = head_text.split("\r\n")
                parts = lines[0].split(" ")
                if len(parts) < 3:
                    break
                method, target, version = parts[0], parts[1], parts[2]

                content_length = 0
                conn_hdr = ""
                for line in lines[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        kl = k.strip().lower()
                        if kl == "content-length":
                            content_length = int(v.strip())
                        elif kl == "connection":
                            conn_hdr = v.strip().lower()

                body = await reader.readexactly(content_length) if content_length > 0 else b""
                status, reason, resp_body, cache_ctl = await self.handle_request(
                    method.upper(), target, body
                )

                keep_alive = (
                    version == "HTTP/1.1" and "close" not in conn_hdr
                ) or "keep-alive" in conn_hdr
                conn_resp = "keep-alive" if keep_alive else "close"
                header = (
                    f"HTTP/1.1 {status} {reason}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(resp_body)}\r\n"
                    f"Cache-Control: {cache_ctl}\r\n"
                    f"Connection: {conn_resp}\r\n\r\n"
                ).encode("latin-1")
                writer.write(header + resp_body)
                await writer.drain()
                if not keep_alive:
                    break
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, ValueError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass


async def run_server(host: str, port: int, db_delay_ms: float, num_rows: int) -> None:
    conn = init_db(num_rows)
    app = MockDbApp(conn, db_delay_ms=db_delay_ms, num_rows=num_rows)
    server = await asyncio.start_server(app.handle_client, host, port, backlog=1024)
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock SQLite DB backend for cache benchmarks")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18081)
    parser.add_argument("--db-delay-ms", type=float, default=10.0)
    parser.add_argument("--rows", type=int, default=5000)
    args = parser.parse_args()
    try:
        asyncio.run(run_server(args.host, args.port, args.db_delay_ms, args.rows))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
