    use super::*;
    use crate::configuration::{
        CachedDescriptorPool, LbStrategy, RouteTarget, UpstreamNode,
    };
    use bytes::{BufMut, BytesMut};
    use http_body_util::Full;
    use hyper::Request;
    use prost::Message;
    use prost_reflect::{
        DescriptorPool, DynamicMessage,
        prost_types::{
            DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
            MethodDescriptorProto, ServiceDescriptorProto,
            field_descriptor_proto::{Label, Type},
        },
    };
    use std::collections::HashSet;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    fn test_descriptor_pool() -> Arc<DescriptorPool> {
        let file = FileDescriptorProto {
            name: Some("user.proto".into()),
            package: Some("user".into()),
            syntax: Some("proto3".into()),
            message_type: vec![
                DescriptorProto {
                    name: Some("UserReq".into()),
                    field: vec![FieldDescriptorProto {
                        name: Some("user_id".into()),
                        json_name: Some("user_id".into()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::String as i32),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("UserRes".into()),
                    field: vec![
                        FieldDescriptorProto {
                            name: Some("id".into()),
                            json_name: Some("id".into()),
                            number: Some(1),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::String as i32),
                            ..Default::default()
                        },
                        FieldDescriptorProto {
                            name: Some("name".into()),
                            json_name: Some("name".into()),
                            number: Some(2),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::String as i32),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
            ],
            service: vec![ServiceDescriptorProto {
                name: Some("UserService".into()),
                method: vec![MethodDescriptorProto {
                    name: Some("GetUser".into()),
                    input_type: Some(".user.UserReq".into()),
                    output_type: Some(".user.UserRes".into()),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        Arc::new(
            DescriptorPool::from_file_descriptor_set(FileDescriptorSet { file: vec![file] })
                .expect("valid descriptor pool"),
        )
    }

    fn test_server_config(request_timeout_seconds: u64) -> Arc<ServerConfig> {
        let toml_str = format!(
            r#"
            name = "agg_test"
            enabled = true
            protocol = "http"
            service = "Router"
            ip = "127.0.0.1"
            port = 8080

            [RouterParams]
            protocol = "http"
            request_timeout_seconds = {request_timeout_seconds}

            [Layers]
            enabled = []
        "#
        );
        let mut cfg: ServerConfig = toml::from_str(&toml_str).unwrap();
        cfg.finalize().unwrap();
        Arc::new(cfg)
    }

    fn build_clients() -> (
        Client<
            common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
            ServiceRespBody,
        >,
        Client<
            common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
            ServiceRespBody,
        >,
    ) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let http_client = common::client::build_hyper_client(
            tls.clone(),
            common::client::ClientPoolConfig::default(),
        );
        let grpc_client = common::client::build_hyper_client(
            tls,
            common::client::ClientPoolConfig {
                http2_only: true,
                ..Default::default()
            },
        );
        (http_client, grpc_client)
    }

    async fn spawn_grpc_user_mock(
        pool: Arc<DescriptorPool>,
        captured_trace: Option<Arc<tokio::sync::Mutex<Option<String>>>>,
    ) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let pool = pool.clone();
                let captured_trace = captured_trace.clone();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(socket);
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(
                        io,
                        hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                            let pool = pool.clone();
                            let captured_trace = captured_trace.clone();
                            async move {
                                if let Some(slot) = captured_trace {
                                    let val = req
                                        .headers()
                                        .get("traceparent")
                                        .and_then(|v| v.to_str().ok())
                                        .map(|s| s.to_string());
                                    *slot.lock().await = val;
                                }
                                let body_bytes = req.into_body().collect().await.unwrap().to_bytes();
                                let mut req_msg =
                                    DynamicMessage::new(pool.get_message_by_name("user.UserReq").unwrap());
                                if body_bytes.len() > 5 {
                                    let len = u32::from_be_bytes([
                                        body_bytes[1],
                                        body_bytes[2],
                                        body_bytes[3],
                                        body_bytes[4],
                                    ]) as usize;
                                    let payload = &body_bytes[5..5 + len];
                                    req_msg.merge(payload).unwrap();
                                }
                                let uid = req_msg
                                    .get_field_by_name("user_id")
                                    .map(|v| v.as_str().unwrap_or("").to_string())
                                    .unwrap_or_default();

                                let mut res_msg =
                                    DynamicMessage::new(pool.get_message_by_name("user.UserRes").unwrap());
                                res_msg.set_field_by_name(
                                    "id",
                                    prost_reflect::Value::String(uid.clone()),
                                );
                                res_msg.set_field_by_name(
                                    "name",
                                    prost_reflect::Value::String(format!("User-{uid}")),
                                );
                                let encoded = res_msg.encode_to_vec();
                                let mut frame = BytesMut::with_capacity(5 + encoded.len());
                                frame.put_u8(0);
                                frame.put_u32(encoded.len() as u32);
                                frame.put_slice(&encoded);

                                Ok::<_, std::convert::Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "application/grpc")
                                        .header("grpc-status", "0")
                                        .body(Full::new(frame.freeze()))
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await;
                });
            }
        });
        port
    }

    async fn spawn_rest_mock(
        status: StatusCode,
        response_body: &'static str,
        delay: Duration,
        captured_uri: Option<Arc<tokio::sync::Mutex<Option<String>>>>,
        captured_trace: Option<Arc<tokio::sync::Mutex<Option<String>>>>,
    ) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let captured_uri = captured_uri.clone();
                let captured_trace = captured_trace.clone();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(socket);
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            io,
                            hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                                let captured_uri = captured_uri.clone();
                                let captured_trace = captured_trace.clone();
                                async move {
                                    if let Some(slot) = captured_uri {
                                        *slot.lock().await = Some(req.uri().to_string());
                                    }
                                    if let Some(slot) = captured_trace {
                                        let val = req
                                            .headers()
                                            .get("traceparent")
                                            .and_then(|v| v.to_str().ok())
                                            .map(|s| s.to_string());
                                        *slot.lock().await = val;
                                    }
                                    if !delay.is_zero() {
                                        tokio::time::sleep(delay).await;
                                    }
                                    Ok::<_, std::convert::Infallible>(
                                        Response::builder()
                                            .status(status)
                                            .header("content-type", "application/json")
                                            .body(Full::new(Bytes::from_static(
                                                response_body.as_bytes(),
                                            )))
                                            .unwrap(),
                                    )
                                }
                            }),
                        )
                        .await;
                });
            }
        });
        port
    }

    fn make_sub_target(
        key: &str,
        backend_type: RouteBackendType,
        port: u16,
        path: &str,
        method: Option<Method>,
        required: bool,
        pool: Option<Arc<DescriptorPool>>,
    ) -> ParsedAggregateTarget {
        let node = UpstreamNode::new(format!("http://127.0.0.1:{port}").parse().unwrap());
        let grpc_pool = pool.map(|p| CachedDescriptorPool {
            pool: p,
            created_at: std::time::Instant::now(),
        });
        let target = Arc::new(RouteTarget {
            upstreams: vec![node],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 60,
            max_retries: 0,
            failure_threshold: 3,
            max_retry_buffer_bytes: 65536,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(grpc_pool),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });
        let target_uri: Uri = path.parse().unwrap();
        let pinned_query_keys: HashSet<String> = target_uri
            .query()
            .filter(|q| !q.is_empty())
            .map(|tq| {
                url::form_urlencoded::parse(tq.as_bytes())
                    .map(|(k, _)| k.into_owned())
                    .collect()
            })
            .unwrap_or_default();
        let json_key_prefix = Bytes::from(format!("{}:", serde_json::to_string(key).unwrap()));
        ParsedAggregateTarget {
            key: key.to_string(),
            json_key_prefix,
            backend_type,
            target,
            target_uri,
            pinned_query_keys,
            method,
            required,
            forward_query: None,
            forward_headers: HashSet::new(),
            timeout_ms: None,
        }
    }

    fn make_aggregate_route(targets: Vec<ParsedAggregateTarget>) -> ParsedRoute {
        let empty_target = Arc::new(RouteTarget {
            upstreams: Vec::new(),
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 10,
            max_retries: 0,
            failure_threshold: 3,
            max_retry_buffer_bytes: 65536,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });
        ParsedRoute {
            prefix: "/api/dashboard".to_string(),
            target: empty_target,
            allowed_roles: Vec::new(),
            backend_type: RouteBackendType::Aggregate,
            aggregate_targets: targets.into_iter().map(Arc::new).collect(),
            aggregate_payload_mode: AggregatePayloadMode::Keyed,
            expose_upstream_errors: false,
            aggregate_deadline_ms: None,
            max_request_bytes: crate::configuration::DEFAULT_MAX_BUFFERED_REQUEST_BYTES,
            max_response_bytes: crate::configuration::DEFAULT_MAX_AGGREGATE_RESPONSE_BYTES,
        }
    }

    #[tokio::test]
    async fn test_aggregate_mixed_grpc_and_rest_post_split_payload() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let pool = test_descriptor_pool();
        let grpc_port = spawn_grpc_user_mock(pool.clone(), None).await;
        let rest_uri_slot = Arc::new(tokio::sync::Mutex::new(None));
        let rest_port = spawn_rest_mock(
            StatusCode::OK,
            r#"[{"id":1,"msg":"hi"}]"#,
            Duration::ZERO,
            Some(rest_uri_slot.clone()),
            None,
        )
        .await;

        let route = make_aggregate_route(vec![
            make_sub_target(
                "user",
                RouteBackendType::GrpcTranscoding,
                grpc_port,
                "/user.UserService/GetUser",
                None,
                true,
                Some(pool),
            ),
            make_sub_target(
                "notifications",
                RouteBackendType::Rest,
                rest_port,
                "/v1/notifications",
                Some(Method::GET),
                false,
                None,
            ),
        ]);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);
        let body = Bytes::from_static(br#"{"user":{"user_id":"42"}}"#);

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(body),
            Method::POST,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        let status = resp.status();
        let json_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            status,
            StatusCode::OK,
            "Unexpected status {}: {}",
            status,
            String::from_utf8_lossy(&json_bytes)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(parsed["user"]["id"], "42");
        assert_eq!(parsed["user"]["name"], "User-42");
        assert_eq!(parsed["notifications"][0]["msg"], "hi");
        assert!(parsed.get("_errors").is_none());
        assert_eq!(
            rest_uri_slot.lock().await.as_deref(),
            Some("/v1/notifications")
        );
    }

    #[tokio::test]
    async fn test_aggregate_get_query_params_to_grpc_and_rest() {
        let pool = test_descriptor_pool();
        let grpc_port = spawn_grpc_user_mock(pool.clone(), None).await;
        let rest_uri_slot = Arc::new(tokio::sync::Mutex::new(None));
        let rest_port = spawn_rest_mock(
            StatusCode::OK,
            r#"{"unread":3}"#,
            Duration::ZERO,
            Some(rest_uri_slot.clone()),
            None,
        )
        .await;

        let route = make_aggregate_route(vec![
            make_sub_target(
                "user",
                RouteBackendType::GrpcTranscoding,
                grpc_port,
                "/user.UserService/GetUser",
                None,
                true,
                Some(pool),
            ),
            make_sub_target(
                "notifications",
                RouteBackendType::Rest,
                rest_port,
                "/v1/notifications",
                None,
                true,
                None,
            ),
        ]);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard?user_id=99".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        let status = resp.status();
        let json_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            status,
            StatusCode::OK,
            "Unexpected status {}: {}",
            status,
            String::from_utf8_lossy(&json_bytes)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(parsed["user"]["id"], "99");
        assert_eq!(parsed["user"]["name"], "User-99");
        assert_eq!(parsed["notifications"]["unread"], 3);
        assert_eq!(
            rest_uri_slot.lock().await.as_deref(),
            Some("/v1/notifications?user_id=99")
        );
    }

    #[tokio::test]
    async fn test_aggregate_optional_failure_returns_null_and_errors_map() {
        let pool = test_descriptor_pool();
        let grpc_port = spawn_grpc_user_mock(pool.clone(), None).await;
        let failing_rest_port = spawn_rest_mock(
            StatusCode::INTERNAL_SERVER_ERROR,
            "notification service down",
            Duration::ZERO,
            None,
            None,
        )
        .await;

        let route = make_aggregate_route(vec![
            make_sub_target(
                "user",
                RouteBackendType::GrpcTranscoding,
                grpc_port,
                "/user.UserService/GetUser",
                None,
                true,
                Some(pool),
            ),
            make_sub_target(
                "notifications",
                RouteBackendType::Rest,
                failing_rest_port,
                "/v1/notifications",
                Some(Method::GET),
                false,
                None,
            ),
        ]);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::from_static(br#"{"user":{"user_id":"7"}}"#)),
            Method::POST,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        let status = resp.status();
        let json_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            status,
            StatusCode::OK,
            "Unexpected status {}: {}",
            status,
            String::from_utf8_lossy(&json_bytes)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(parsed["user"]["id"], "7");
        assert!(parsed["notifications"].is_null());
        assert_eq!(parsed["_errors"]["notifications"]["status"], 500);
        // F4: raw upstream body ("notification service down") must NOT leak by default
        assert_eq!(
            parsed["_errors"]["notifications"]["message"],
            "Internal Server Error"
        );
    }

    #[tokio::test]
    async fn test_aggregate_required_failure_aborts_immediately() {
        let dead_port = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let slow_rest_port = spawn_rest_mock(
            StatusCode::OK,
            r#"{"ok":true}"#,
            Duration::from_secs(5),
            None,
            None,
        )
        .await;

        let route = make_aggregate_route(vec![
            make_sub_target(
                "required_svc",
                RouteBackendType::Rest,
                dead_port,
                "/v1/req",
                Some(Method::GET),
                true,
                None,
            ),
            make_sub_target(
                "slow_svc",
                RouteBackendType::Rest,
                slow_rest_port,
                "/v1/slow",
                Some(Method::GET),
                false,
                None,
            ),
        ]);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(10);

        let start = std::time::Instant::now();
        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(10)),
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "Required failure must abort remaining slow sub-requests immediately"
        );
    }

    #[tokio::test]
    async fn test_aggregate_propagates_trace_headers_to_all_targets() {
        let pool = test_descriptor_pool();
        let grpc_trace = Arc::new(tokio::sync::Mutex::new(None));
        let rest_trace = Arc::new(tokio::sync::Mutex::new(None));

        let grpc_port = spawn_grpc_user_mock(pool.clone(), Some(grpc_trace.clone())).await;
        let rest_port = spawn_rest_mock(
            StatusCode::OK,
            r#"{"ok":true}"#,
            Duration::ZERO,
            None,
            Some(rest_trace.clone()),
        )
        .await;

        let route = make_aggregate_route(vec![
            make_sub_target(
                "user",
                RouteBackendType::GrpcTranscoding,
                grpc_port,
                "/user.UserService/GetUser",
                None,
                true,
                Some(pool),
            ),
            make_sub_target(
                "notifications",
                RouteBackendType::Rest,
                rest_port,
                "/v1/notifications",
                Some(Method::GET),
                true,
                None,
            ),
        ]);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "traceparent",
            hyper::header::HeaderValue::from_static(traceparent),
        );

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::from_static(br#"{"user":{"user_id":"1"}}"#)),
            Method::POST,
            Version::HTTP_11,
            headers,
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(grpc_trace.lock().await.as_deref(), Some(traceparent));
        assert_eq!(rest_trace.lock().await.as_deref(), Some(traceparent));
    }

    #[tokio::test]
    async fn test_aggregate_invalid_json_from_rest_upstream_required_and_optional() {
        let bad_json_port = spawn_rest_mock(
            StatusCode::OK,
            "<html>not json</html>",
            Duration::ZERO,
            None,
            None,
        )
        .await;
        let ok_port = spawn_rest_mock(
            StatusCode::OK,
            r#"{"ok":true}"#,
            Duration::ZERO,
            None,
            None,
        )
        .await;

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        // Case A: required = true -> 502 Bad Gateway
        let route_req = make_aggregate_route(vec![make_sub_target(
            "bad",
            RouteBackendType::Rest,
            bad_json_port,
            "/v1/bad",
            Some(Method::GET),
            true,
            None,
        )]);
        let resp_req = handle_aggregate(
            &route_req,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();
        assert_eq!(resp_req.status(), StatusCode::BAD_GATEWAY);

        // Case B: required = false -> 200 OK with null + _errors (502)
        let route_opt = make_aggregate_route(vec![
            make_sub_target(
                "good",
                RouteBackendType::Rest,
                ok_port,
                "/v1/ok",
                Some(Method::GET),
                true,
                None,
            ),
            make_sub_target(
                "bad",
                RouteBackendType::Rest,
                bad_json_port,
                "/v1/bad",
                Some(Method::GET),
                false,
                None,
            ),
        ]);
        let resp_opt = handle_aggregate(
            &route_opt,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();
        assert_eq!(resp_opt.status(), StatusCode::OK);
        let json_bytes = resp_opt.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(parsed["good"]["ok"], true);
        assert!(parsed["bad"].is_null());
        assert_eq!(parsed["_errors"]["bad"]["status"], 502);
        assert!(
            parsed["_errors"]["bad"]["message"]
                .as_str()
                .unwrap()
                .contains("invalid JSON")
        );
    }

    #[tokio::test]
    async fn test_aggregate_optional_timeout_returns_null_and_504_in_errors() {
        let ok_port = spawn_rest_mock(
            StatusCode::OK,
            r#"{"fast":1}"#,
            Duration::ZERO,
            None,
            None,
        )
        .await;
        let slow_port = spawn_rest_mock(
            StatusCode::OK,
            r#"{"slow":2}"#,
            Duration::from_millis(600),
            None,
            None,
        )
        .await;

        let route = make_aggregate_route(vec![
            make_sub_target(
                "fast",
                RouteBackendType::Rest,
                ok_port,
                "/v1/fast",
                Some(Method::GET),
                true,
                None,
            ),
            make_sub_target(
                "slow",
                RouteBackendType::Rest,
                slow_port,
                "/v1/slow",
                Some(Method::GET),
                false,
                None,
            ),
        ]);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_millis(150)),
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let json_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(parsed["fast"]["fast"], 1);
        assert!(parsed["slow"].is_null());
        assert_eq!(parsed["_errors"]["slow"]["status"], 504);
    }

    #[tokio::test]
    async fn test_aggregate_method_not_allowed_returns_405() {
        let route = make_aggregate_route(vec![]);
        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        for method in [Method::PUT, Method::DELETE, Method::PATCH] {
            let resp = handle_aggregate(
                &route,
                RequestBody::Buffered(Bytes::new()),
                method,
                Version::HTTP_11,
                hyper::HeaderMap::new(),
                &"/api/dashboard".parse().unwrap(),
                None,
                "agg_test",
                &http_client,
                &grpc_client,
                &cfg,
                Some(Duration::from_secs(5)),
            )
            .await
            .unwrap();
            assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        }
    }

    #[tokio::test]
    async fn test_aggregate_rest_post_flat_payload_forwarding_and_header_sanitizing() {
        let captured = Arc::new(tokio::sync::Mutex::new(None::<(
            Option<String>,
            Option<String>,
            Bytes,
        )>));
        let captured_srv = captured.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                let io = hyper_util::rt::TokioIo::new(socket);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                            let captured_srv = captured_srv.clone();
                            async move {
                                let cl = req
                                    .headers()
                                    .get(header::CONTENT_LENGTH)
                                    .and_then(|v| v.to_str().ok())
                                    .map(|s| s.to_string());
                                let ae = req
                                    .headers()
                                    .get(header::ACCEPT_ENCODING)
                                    .and_then(|v| v.to_str().ok())
                                    .map(|s| s.to_string());
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                *captured_srv.lock().await = Some((cl, ae, body));
                                Ok::<_, std::convert::Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "application/json")
                                        .body(Full::new(Bytes::from_static(br#"{"saved":true}"#)))
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await;
            }
        });

        let mut route = make_aggregate_route(vec![make_sub_target(
            "audit",
            RouteBackendType::Rest,
            port,
            "/v1/audit",
            Some(Method::POST),
            true,
            None,
        )]);
        route.aggregate_payload_mode = AggregatePayloadMode::Broadcast;

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        let flat_body = Bytes::from_static(br#"{"user_id":"42","action":"login"}"#);
        let mut headers = hyper::HeaderMap::new();
        headers.insert(header::ACCEPT_ENCODING, header::HeaderValue::from_static("gzip, br"));
        // Deliberately mismatched Content-Length to verify sanitizer recomputes it
        headers.insert(header::CONTENT_LENGTH, header::HeaderValue::from_static("9999"));

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(flat_body.clone()),
            Method::POST,
            Version::HTTP_11,
            headers,
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let json_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(parsed["audit"]["saved"], true);

        let (got_cl, got_ae, got_body) = captured.lock().await.clone().unwrap();
        assert_eq!(got_cl.as_deref(), Some(flat_body.len().to_string().as_str()));
        assert_eq!(got_ae, None, "Accept-Encoding must be stripped for REST aggregate sub-calls");
        assert_eq!(got_body, flat_body);
    }

    /// Regression test for F1 (REST & gRPC): in default `Keyed` mode, a target whose key is
    /// absent from the request body must receive `{}` and NEVER sibling targets' payloads,
    /// and unknown top-level keys must be rejected with 400 Bad Request before fanning out.
    #[tokio::test]
    async fn test_aggregate_f1_keyed_mode_isolates_payloads_and_rejects_unknown_keys() {
        let body_a = Arc::new(tokio::sync::Mutex::new(None::<Bytes>));
        let body_b = Arc::new(tokio::sync::Mutex::new(None::<Bytes>));

        let spawn_capture = |slot: Arc<tokio::sync::Mutex<Option<Bytes>>>| async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        break;
                    };
                    let slot = slot.clone();
                    tokio::spawn(async move {
                        let io = hyper_util::rt::TokioIo::new(socket);
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(
                                io,
                                hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                                    let slot = slot.clone();
                                    async move {
                                        let b = req.into_body().collect().await.unwrap().to_bytes();
                                        *slot.lock().await = Some(b);
                                        Ok::<_, std::convert::Infallible>(
                                            Response::builder()
                                                .status(StatusCode::OK)
                                                .header("content-type", "application/json")
                                                .body(Full::new(Bytes::from_static(br#"{"ok":true}"#)))
                                                .unwrap(),
                                        )
                                    }
                                }),
                            )
                            .await;
                    });
                }
            });
            port
        };

        let port_a = spawn_capture(body_a.clone()).await;
        let port_b = spawn_capture(body_b.clone()).await;
        let pool = test_descriptor_pool();
        let grpc_port = spawn_grpc_user_mock(pool.clone(), None).await;

        let route = make_aggregate_route(vec![
            make_sub_target("a", RouteBackendType::Rest, port_a, "/in", Some(Method::POST), true, None),
            make_sub_target("b", RouteBackendType::Rest, port_b, "/in", Some(Method::POST), true, None),
            make_sub_target(
                "user",
                RouteBackendType::GrpcTranscoding,
                grpc_port,
                "/user.UserService/GetUser",
                None,
                true,
                Some(pool),
            ),
        ]);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        // 1. Only key "a" present: "a" gets its sub-object, "b" and gRPC "user" get "{}" (no leak, no gRPC 400)
        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::from_static(br#"{"a":{"secret_for_a":"s3cr3t"}}"#)),
            Method::POST,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_a.lock().await.as_deref(),
            Some(&br#"{"secret_for_a":"s3cr3t"}"#[..])
        );
        assert_eq!(
            body_b.lock().await.as_deref(),
            Some(&b"{}"[..]),
            "Target without own key must receive '{{}}', never sibling payload"
        );

        // 2. Unknown top-level key in Keyed mode -> 400 Bad Request
        let bad_resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::from_static(br#"{"unknown_key":{"x":1}}"#)),
            Method::POST,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();
        assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Regression test for F4: raw upstream error bodies (stack traces, hostnames, credentials)
    /// must NOT leak to clients by default, and are only reflected when `expose_upstream_errors = true`.
    #[tokio::test]
    async fn test_aggregate_f4_sanitizes_upstream_error_bodies_by_default() {
        let leak_port = spawn_rest_mock(
            StatusCode::INTERNAL_SERVER_ERROR,
            "panic at db-prod-01.internal:5432 user=svc_orders pw=hunter2",
            Duration::ZERO,
            None,
            None,
        )
        .await;

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        // Required target with expose_upstream_errors = false (default)
        let route_req = make_aggregate_route(vec![make_sub_target(
            "t",
            RouteBackendType::Rest,
            leak_port,
            "/x",
            Some(Method::GET),
            true,
            None,
        )]);
        let resp_req = handle_aggregate(
            &route_req,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();
        assert_eq!(resp_req.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let req_text = String::from_utf8(
            resp_req.into_body().collect().await.unwrap().to_bytes().to_vec(),
        )
        .unwrap();
        assert!(!req_text.contains("hunter2"));
        assert!(!req_text.contains("db-prod-01"));
        assert_eq!(req_text, "Internal Server Error");

        // Optional target with expose_upstream_errors = false (default)
        let mut route_opt = make_aggregate_route(vec![make_sub_target(
            "t",
            RouteBackendType::Rest,
            leak_port,
            "/x",
            Some(Method::GET),
            false,
            None,
        )]);
        let resp_opt = handle_aggregate(
            &route_opt,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();
        assert_eq!(resp_opt.status(), StatusCode::OK);
        let opt_bytes = resp_opt.into_body().collect().await.unwrap().to_bytes();
        let opt_text = String::from_utf8(opt_bytes.to_vec()).unwrap();
        assert!(!opt_text.contains("hunter2"));
        let parsed: serde_json::Value = serde_json::from_slice(&opt_bytes).unwrap();
        assert_eq!(parsed["_errors"]["t"]["message"], "Internal Server Error");

        // Explicit opt-in: expose_upstream_errors = true
        route_opt.expose_upstream_errors = true;
        let resp_exposed = handle_aggregate(
            &route_opt,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();
        let exposed_bytes = resp_exposed.into_body().collect().await.unwrap().to_bytes();
        let exposed_parsed: serde_json::Value = serde_json::from_slice(&exposed_bytes).unwrap();
        assert!(
            exposed_parsed["_errors"]["t"]["message"]
                .as_str()
                .unwrap()
                .contains("db-prod-01")
        );
    }

    /// Regression test for F2: operator-pinned query parameters in `target.path` take
    /// precedence over client query parameters (no parameter pollution), and `forward_query`
    /// allowlists restrict which client parameters reach a target.
    #[tokio::test]
    async fn test_aggregate_f2_query_precedence_and_allowlist() {
        let uri_pinned = Arc::new(tokio::sync::Mutex::new(None));
        let uri_filtered = Arc::new(tokio::sync::Mutex::new(None));

        let p1 = spawn_rest_mock(
            StatusCode::OK,
            r#"{"ok":1}"#,
            Duration::ZERO,
            Some(uri_pinned.clone()),
            None,
        )
        .await;
        let p2 = spawn_rest_mock(
            StatusCode::OK,
            r#"{"ok":2}"#,
            Duration::ZERO,
            Some(uri_filtered.clone()),
            None,
        )
        .await;

        let t1 = make_sub_target(
            "pinned",
            RouteBackendType::Rest,
            p1,
            "/v1/items?tenant=acme",
            Some(Method::GET),
            true,
            None,
        );
        let mut t2 = make_sub_target(
            "filtered",
            RouteBackendType::Rest,
            p2,
            "/v1/items",
            Some(Method::GET),
            true,
            None,
        );
        t2.forward_query = Some(HashSet::from(["allowed".to_string()]));

        let route = make_aggregate_route(vec![t1, t2]);
        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard?tenant=evil&allowed=yes&dropped=no"
                .parse()
                .unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let seen1 = uri_pinned.lock().await.clone().unwrap();
        assert!(seen1.contains("tenant=acme"), "pinned param preserved: {seen1}");
        assert!(
            !seen1.contains("tenant=evil"),
            "client must not pollute operator-pinned query param: {seen1}"
        );
        assert!(seen1.contains("allowed=yes"), "non-conflicting param forwarded: {seen1}");

        let seen2 = uri_filtered.lock().await.clone().unwrap();
        assert_eq!(seen2, "/v1/items?allowed=yes");
    }

    /// Regression test for F3: client `Authorization`/`Cookie` headers are stripped by default
    /// (unless opted in per target via `forward_headers`), and conditional headers (`If-None-Match`)
    /// are always stripped so no single target returns `304 Not Modified`.
    #[tokio::test]
    async fn test_aggregate_f3_strips_credentials_and_conditional_headers_by_default() {
        let capture = |slot: Arc<tokio::sync::Mutex<Option<hyper::HeaderMap>>>| async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                if let Ok((socket, _)) = listener.accept().await {
                    let io = hyper_util::rt::TokioIo::new(socket);
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            io,
                            hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                                let slot = slot.clone();
                                async move {
                                    let hdrs = req.headers().clone();
                                    let is_cond = hdrs.contains_key(header::IF_NONE_MATCH);
                                    *slot.lock().await = Some(hdrs);
                                    if is_cond {
                                        return Ok::<_, std::convert::Infallible>(
                                            Response::builder()
                                                .status(StatusCode::NOT_MODIFIED)
                                                .body(Full::new(Bytes::new()))
                                                .unwrap(),
                                        );
                                    }
                                    Ok::<_, std::convert::Infallible>(
                                        Response::builder()
                                            .status(StatusCode::OK)
                                            .header("content-type", "application/json")
                                            .body(Full::new(Bytes::from_static(br#"{"v":1}"#)))
                                            .unwrap(),
                                    )
                                }
                            }),
                        )
                        .await;
                }
            });
            port
        };

        let h_default = Arc::new(tokio::sync::Mutex::new(None));
        let h_optin = Arc::new(tokio::sync::Mutex::new(None));
        let p_default = capture(h_default.clone()).await;
        let p_optin = capture(h_optin.clone()).await;

        let t_default = make_sub_target(
            "untrusted",
            RouteBackendType::Rest,
            p_default,
            "/x",
            Some(Method::GET),
            true,
            None,
        );
        let mut t_optin = make_sub_target(
            "trusted",
            RouteBackendType::Rest,
            p_optin,
            "/y",
            Some(Method::GET),
            true,
            None,
        );
        t_optin.forward_headers.insert("authorization".to_string());

        let route = make_aggregate_route(vec![t_default, t_optin]);
        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer SECRET-TOKEN"),
        );
        headers.insert(
            header::COOKIE,
            header::HeaderValue::from_static("sid=SECRET-COOKIE"),
        );
        headers.insert(
            header::IF_NONE_MATCH,
            header::HeaderValue::from_static("\"etag-1\""),
        );

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            headers,
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), StatusCode::OK, "If-None-Match must be stripped");

        let got_default = h_default.lock().await.clone().unwrap();
        assert!(!got_default.contains_key(header::AUTHORIZATION));
        assert!(!got_default.contains_key(header::COOKIE));
        assert!(!got_default.contains_key(header::IF_NONE_MATCH));

        let got_optin = h_optin.lock().await.clone().unwrap();
        assert_eq!(
            got_optin.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()),
            Some("Bearer SECRET-TOKEN")
        );
        assert!(!got_optin.contains_key(header::COOKIE));
        assert!(!got_optin.contains_key(header::IF_NONE_MATCH));
    }

    /// Regression tests for F5: gRPC status codes in both Trailers-Only initial headers
    /// (`NOT_FOUND` -> 404 + `grpc_status: 5`) and trailing headers after a data frame
    /// (`INTERNAL` -> 502 + `grpc_status: 13`, never silent partial success) must be evaluated.
    #[tokio::test]
    async fn test_aggregate_f5_evaluates_grpc_status_trailers_only_and_trailing_errors() {
        use http_body::Frame;

        async fn spawn_grpc_status_mock(
            trailers_only: Option<&'static str>,
            trailing_after_data: Option<&'static str>,
        ) -> u16 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    let Ok((sock, _)) = listener.accept().await else {
                        break;
                    };
                    tokio::spawn(async move {
                        let io = hyper_util::rt::TokioIo::new(sock);
                        let _ = hyper::server::conn::http2::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(
                            io,
                            hyper::service::service_fn(
                                move |req: Request<hyper::body::Incoming>| async move {
                                    let _ = req.into_body().collect().await;
                                    let mut frames: Vec<Result<Frame<Bytes>, std::convert::Infallible>> =
                                        Vec::new();
                                    let mut builder = Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "application/grpc");
                                    if let Some(code) = trailers_only {
                                        builder = builder
                                            .header("grpc-status", code)
                                            .header("grpc-message", "user%20not%20found");
                                    } else {
                                        // Valid UserRes{ id: "x" } frame followed by error trailer
                                        frames.push(Ok(Frame::data(Bytes::from_static(&[
                                            0, 0, 0, 0, 3, 0x0a, 0x01, 0x78,
                                        ]))));
                                        let mut trailers = hyper::HeaderMap::new();
                                        trailers.insert(
                                            "grpc-status",
                                            trailing_after_data.unwrap_or("0").parse().unwrap(),
                                        );
                                        trailers.insert(
                                            "grpc-message",
                                            "internal%20failure".parse().unwrap(),
                                        );
                                        frames.push(Ok(Frame::trailers(trailers)));
                                    }
                                    let body = http_body_util::StreamBody::new(
                                        futures_util::stream::iter(frames),
                                    );
                                    Ok::<_, std::convert::Infallible>(builder.body(body).unwrap())
                                },
                            ),
                        )
                        .await;
                    });
                }
            });
            port
        }

        let pool = test_descriptor_pool();
        let not_found_port = spawn_grpc_status_mock(Some("5"), None).await;
        let trailing_err_port = spawn_grpc_status_mock(None, Some("13")).await;

        let route = make_aggregate_route(vec![
            make_sub_target(
                "missing",
                RouteBackendType::GrpcTranscoding,
                not_found_port,
                "/user.UserService/GetUser",
                None,
                false,
                Some(pool.clone()),
            ),
            make_sub_target(
                "broken",
                RouteBackendType::GrpcTranscoding,
                trailing_err_port,
                "/user.UserService/GetUser",
                None,
                false,
                Some(pool),
            ),
        ]);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard?user_id=42".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // Trailers-Only NOT_FOUND (5) -> HTTP 404 + grpc_status 5 (sanitized reason phrase by default)
        assert!(parsed["missing"].is_null());
        assert_eq!(parsed["_errors"]["missing"]["status"], 404);
        assert_eq!(parsed["_errors"]["missing"]["grpc_status"], 5);
        assert_eq!(parsed["_errors"]["missing"]["message"], "Not Found");

        // Trailing INTERNAL (13) after data frame -> must NOT be treated as success!
        assert!(parsed["broken"].is_null());
        assert_eq!(parsed["_errors"]["broken"]["status"], 502);
        assert_eq!(parsed["_errors"]["broken"]["grpc_status"], 13);
    }

    /// Regression test for P3: per-target `timeout_ms` and route-wide `aggregate_deadline_ms`
    /// prevent a slow optional target from blocking the entire aggregated response.
    #[tokio::test]
    async fn test_aggregate_p3_per_target_timeout_and_route_deadline_cap_optional_latency() {
        let fast_port = spawn_rest_mock(
            StatusCode::OK,
            r#"{"fast":true}"#,
            Duration::ZERO,
            None,
            None,
        )
        .await;
        let slow_port = spawn_rest_mock(
            StatusCode::OK,
            r#"{"slow":true}"#,
            Duration::from_secs(3),
            None,
            None,
        )
        .await;

        let t_fast = make_sub_target(
            "fast",
            RouteBackendType::Rest,
            fast_port,
            "/v1/fast",
            Some(Method::GET),
            true,
            None,
        );
        let mut t_slow = make_sub_target(
            "slow_opt",
            RouteBackendType::Rest,
            slow_port,
            "/v1/slow",
            Some(Method::GET),
            false,
            None,
        );
        t_slow.timeout_ms = Some(120);

        let mut route = make_aggregate_route(vec![t_fast, t_slow]);
        route.aggregate_deadline_ms = Some(250);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(10);

        let start = std::time::Instant::now();
        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(10)),
        )
        .await
        .unwrap();

        let elapsed = start.elapsed();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            elapsed < Duration::from_millis(900),
            "Slow optional target must be bounded by timeout_ms/deadline_ms (took {elapsed:?})"
        );

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["fast"]["fast"], true);
        assert!(parsed["slow_opt"].is_null());
        assert_eq!(parsed["_errors"]["slow_opt"]["status"], 504);
    }

    /// Regression test for M1: cumulative `max_response_bytes` cap prevents RAM amplification
    /// across multiple sub-targets.
    #[tokio::test]
    async fn test_aggregate_m1_enforces_cumulative_max_response_bytes() {
        let p1 = spawn_rest_mock(
            StatusCode::OK,
            r#"{"data":"12345678901234567890"}"#, // 31 bytes
            Duration::ZERO,
            None,
            None,
        )
        .await;
        let p2 = spawn_rest_mock(
            StatusCode::OK,
            r#"{"data":"abcdefghijklmnopqrstuvwxyz"}"#, // 37 bytes
            Duration::ZERO,
            None,
            None,
        )
        .await;

        let mut route = make_aggregate_route(vec![
            make_sub_target("a", RouteBackendType::Rest, p1, "/a", Some(Method::GET), true, None),
            make_sub_target("b", RouteBackendType::Rest, p2, "/b", Some(Method::GET), true, None),
        ]);
        // Each individual response fits under 50 bytes, but their sum (68 bytes) exceeds the cap!
        route.max_response_bytes = 50;

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// Verifies that both `parse_keyed_payload` (request splitting) and `assemble_aggregated_body`
    /// (response assembly) operate in true zero-copy mode by asserting pointer identity against
    /// the original `Bytes` buffers.
    #[test]
    fn test_aggregate_zero_copy_pointer_identity_for_request_slices_and_response_chunks() {
        let route = make_aggregate_route(vec![
            make_sub_target("alpha", RouteBackendType::Rest, 8081, "/a", Some(Method::POST), true, None),
            make_sub_target("beta", RouteBackendType::Rest, 8082, "/b", Some(Method::POST), true, None),
        ]);

        // 1. Request slicing: sub-slice pointers must lie strictly within `raw_req` buffer
        let raw_req = Bytes::from_static(br#"{"alpha":{"id":101},"beta":[1,2,3]}"#);
        let req_range = raw_req.as_ptr_range();
        let slices = parse_keyed_payload(&raw_req, &route.aggregate_targets)
            .expect("valid keyed payload")
            .expect("non-empty payload");

        let slice_alpha = slices[0].as_ref().expect("alpha slice");
        let slice_beta = slices[1].as_ref().expect("beta slice");
        assert_eq!(slice_alpha.as_ref(), br#"{"id":101}"#);
        assert_eq!(slice_beta.as_ref(), br#"[1,2,3]"#);
        assert!(
            req_range.contains(&slice_alpha.as_ptr()),
            "alpha request slice must point directly into raw_req (zero-copy)"
        );
        assert!(
            req_range.contains(&slice_beta.as_ptr()),
            "beta request slice must point directly into raw_req (zero-copy)"
        );

        // 2. Response assembly: upstream `Bytes` payloads must be moved into `ChunkedBytesBody`
        // without copying (`chunk.as_ptr() == upstream_bytes.as_ptr()`).
        let up_alpha = Bytes::from(vec![b'{', b'"', b'k', b'"', b':', b'1', b'}']);
        let up_beta = Bytes::from(vec![b'{', b'"', b'k', b'"', b':', b'2', b'}']);
        let ptr_alpha = up_alpha.as_ptr();
        let ptr_beta = up_beta.as_ptr();

        let global_budget = BufferBudget::new(1024);
        let body = assemble_aggregated_body(
            &route.aggregate_targets,
            vec![
                Some(SubOutcome::Success(
                    up_alpha,
                    BufferReservation::new(Arc::clone(&global_budget)),
                )),
                Some(SubOutcome::Success(
                    up_beta,
                    BufferReservation::new(Arc::clone(&global_budget)),
                )),
            ],
            &global_budget,
        )
        .expect("assemble_aggregated_body");

        assert!(
            body.chunks.iter().any(|c| c.as_ptr() == ptr_alpha),
            "alpha upstream response buffer must be preserved without copying"
        );
        assert!(
            body.chunks.iter().any(|c| c.as_ptr() == ptr_beta),
            "beta upstream response buffer must be preserved without copying"
        );
    }

    /// Edge cases of the zero-copy keyed request splitter: escaped keys, duplicate keys,
    /// non-object roots, trailing garbage, unknown keys, and error-classification robustness.
    #[test]
    fn test_parse_keyed_payload_edge_cases() {
        let route = make_aggregate_route(vec![
            make_sub_target("alpha", RouteBackendType::Rest, 1, "/a", Some(Method::POST), true, None),
            make_sub_target("beta", RouteBackendType::Rest, 2, "/b", Some(Method::POST), true, None),
        ]);
        let targets = &route.aggregate_targets;
        const NOT_OBJ: &str = "Bad Request: Aggregate keyed payload must be a JSON object";
        const UNKNOWN: &str = "Bad Request: Unknown target key in aggregate payload";
        let parse = |s: &'static str| parse_keyed_payload(&Bytes::from_static(s.as_bytes()), targets);

        // Empty body => no keyed payload at all.
        assert!(matches!(parse(""), Ok(None)));

        // Escaped key (`\u0061lpha` == "alpha") resolves to the right target; whitespace preserved.
        let slots = parse(r#"{ "\u0061lpha" : { "x" : 1 } }"#).unwrap().unwrap();
        assert_eq!(slots[0].as_deref(), Some(&br#"{ "x" : 1 }"#[..]));
        assert!(slots[1].is_none());

        // Duplicate keys: last occurrence wins (same as serde_json::Value semantics before).
        let slots = parse(r#"{"alpha":1,"alpha":2}"#).unwrap().unwrap();
        assert_eq!(slots[0].as_deref(), Some(&b"2"[..]));

        // Non-object roots and invalid JSON => "must be a JSON object".
        for bad in ["[1]", "null", "42", "\"str\"", "  ", "{", r#"{"alpha":}"#] {
            assert_eq!(parse(bad).unwrap_err(), NOT_OBJ, "input: {bad:?}");
        }
        // Trailing garbage after a valid object is rejected.
        assert_eq!(parse(r#"{"alpha":1} x"#).unwrap_err(), NOT_OBJ);

        // Unknown top-level key => dedicated message.
        assert_eq!(parse(r#"{"gamma":1}"#).unwrap_err(), UNKNOWN);
        // A string body that merely *contains* the old sentinel text must not be misclassified.
        assert_eq!(parse("\"unknown_target_key\"").unwrap_err(), NOT_OBJ);
        // A valid body whose *value* contains the sentinel is fine.
        assert!(parse(r#"{"alpha":"unknown_target_key"}"#).unwrap().is_some());
    }

    /// Verifies that `SharedBudgetBody` enforces the cumulative budget mid-stream as frames
    /// arrive (across concurrent readers), aborting before remaining chunks are buffered into RAM.
    #[tokio::test]
    async fn test_shared_budget_body_aborts_mid_stream_across_concurrent_readers() {
        let budget = Arc::new(AtomicUsize::new(35));
        let chunks_pulled_a = Arc::new(AtomicUsize::new(0));
        let chunks_pulled_b = Arc::new(AtomicUsize::new(0));

        let make_stream = |counter: Arc<AtomicUsize>| {
            let s = futures_util::stream::unfold(0usize, move |idx| {
                let counter = Arc::clone(&counter);
                async move {
                    if idx >= 10 {
                        return None;
                    }
                    counter.fetch_add(1, Ordering::Relaxed);
                    // Yield 20 bytes per chunk (10 chunks = 200 bytes total if unguarded)
                    let frame = http_body::Frame::data(Bytes::from(vec![b'x'; 20]));
                    Some((Ok::<_, SrvError>(frame), idx + 1))
                }
            });
            http_body_util::StreamBody::new(s).boxed()
        };

        let exceeded_a = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let exceeded_b = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let global_budget = BufferBudget::new(1024);
        let mut res_guard_a = BufferReservation::new(Arc::clone(&global_budget));
        let mut res_guard_b = BufferReservation::new(Arc::clone(&global_budget));
        let mut global_exc_a = false;
        let mut global_exc_b = false;

        let body_a = SharedBudgetBody {
            inner: make_stream(Arc::clone(&chunks_pulled_a)),
            remaining_budget: Arc::clone(&budget),
            exceeded: Arc::clone(&exceeded_a),
            reservation: &mut res_guard_a,
            global_exceeded: &mut global_exc_a,
        };
        let body_b = SharedBudgetBody {
            inner: make_stream(Arc::clone(&chunks_pulled_b)),
            remaining_budget: Arc::clone(&budget),
            exceeded: Arc::clone(&exceeded_b),
            reservation: &mut res_guard_b,
            global_exceeded: &mut global_exc_b,
        };

        let (res_a, res_b) = tokio::join!(body_a.collect(), body_b.collect());
        assert!(
            res_a.is_err() || res_b.is_err(),
            "Cumulative shared budget (35 B) must reject multi-chunk streams mid-flight"
        );
        assert!(
            exceeded_a.load(Ordering::Relaxed) || exceeded_b.load(Ordering::Relaxed),
            "At least one reader must flag budget exceeded"
        );
        // Combined pulled chunks must be at most 3 (1+1 within budget, plus the first overflowing chunk)
        let total_pulled =
            chunks_pulled_a.load(Ordering::Relaxed) + chunks_pulled_b.load(Ordering::Relaxed);
        assert!(
            total_pulled <= 3,
            "SharedBudgetBody must stop pulling before buffering remaining chunks (pulled {total_pulled}/20)"
        );
    }

    #[tokio::test]
    async fn test_shared_budget_body_enforces_global_buffer_budget_and_releases_on_drop() {
        let route_budget = Arc::new(AtomicUsize::new(10_000));
        let global_budget = BufferBudget::new(30);

        let sub_target = make_sub_target(
            "orders",
            RouteBackendType::Rest,
            8080,
            "/orders",
            Some(Method::GET),
            true,
            None,
        );

        // 40-byte JSON response fits easily in route_budget (10_000), but exceeds global_budget (30).
        let payload = Bytes::from_static(br#"{"orders":[1,2,3,4,5,6,7,8,9,10,11,12]}"#);
        let resp = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(payload).map_err(SrvError::from).boxed())
            .unwrap();

        let outcome = collect_sub_outcome(
            &sub_target,
            resp,
            Some(Duration::from_secs(1)),
            10_000,
            route_budget,
            Arc::clone(&global_budget),
            false,
        )
        .await;

        match outcome {
            SubOutcome::Failed { status, .. } => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            }
            SubOutcome::Success(_, _) => panic!("Expected 503 when global buffer budget is exhausted"),
        }

        // RAII drop of the failed sub-target's BufferReservation must restore the full global budget.
        assert_eq!(global_budget.remaining(), 30);
    }

    #[tokio::test]
    async fn test_chunked_bytes_body_releases_global_budget_incrementally_and_on_early_drop() {
        let route = make_aggregate_route(vec![
            make_sub_target("alpha", RouteBackendType::Rest, 8081, "/a", Some(Method::GET), true, None),
            make_sub_target("beta", RouteBackendType::Rest, 8082, "/b", Some(Method::GET), true, None),
        ]);
        let global_budget = BufferBudget::new(200);

        let mut res_a = BufferReservation::new(Arc::clone(&global_budget));
        assert!(res_a.try_reserve(40));
        let mut res_b = BufferReservation::new(Arc::clone(&global_budget));
        assert!(res_b.try_reserve(60));
        assert_eq!(global_budget.remaining(), 100);

        let mut body = assemble_aggregated_body(
            &route.aggregate_targets,
            vec![
                Some(SubOutcome::Success(Bytes::from(vec![b'1'; 40]), res_a)),
                Some(SubOutcome::Success(Bytes::from(vec![b'2'; 60]), res_b)),
            ],
            &global_budget,
        )
        .expect("assemble_aggregated_body");

        // Poll only the first two framing chunks ("{" and "\"alpha\":"), then drop the body early
        // (simulating a client disconnecting mid-stream) and verify 100% of the budget is restored.
        let _ = body.frame().await;
        let _ = body.frame().await;
        assert!(global_budget.remaining() > 100);
        drop(body);
        assert_eq!(global_budget.remaining(), 200);
    }
