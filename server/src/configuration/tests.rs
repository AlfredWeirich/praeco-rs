    use super::*;

    #[test]
    fn test_server_with_tunnel_optional_ip_port() {
        let toml_str = r#"
            name = "tunnel_server"
            enabled = true
            protocol = "http"
            service = "Echo"

            [tunnel]
            target_url = "tls://localhost:7001"
            sni_domain = "example.com"
            client_cert_path = "dummy.pem"
            client_key_path = "dummy.key"
            ca_cert_path = "dummy_ca.pem"

            [Layers]
            enabled = []
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        assert!(server.ip.is_none());
        assert!(server.port.is_none());
        assert!(server.finalize().is_ok());
        assert_eq!(server.tunnel.as_ref().unwrap().max_yamux_streams, None);
        assert!(server.tunnel.as_ref().unwrap().proxy_protocol);
    }

    #[test]
    fn test_tunnel_config_custom_max_yamux_streams() {
        let toml_str = r#"
            name = "custom_tunnel_server"
            enabled = true
            protocol = "http"
            service = "Echo"

            [tunnel]
            target_url = "tls://localhost:7001"
            sni_domain = "example.com"
            client_cert_path = "dummy.pem"
            client_key_path = "dummy.key"
            ca_cert_path = "dummy_ca.pem"
            max_yamux_streams = 8192

            [Layers]
            enabled = []
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        assert!(server.finalize().is_ok());
        assert_eq!(server.tunnel.as_ref().unwrap().max_yamux_streams, Some(8192));
    }

    #[test]
    fn test_server_without_tunnel_requires_ip_and_port() {
        let toml_str = r#"
            name = "listen_server"
            enabled = true
            protocol = "http"
            service = "Echo"

            [Layers]
            enabled = []
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        assert!(server.ip.is_none());
        assert!(server.port.is_none());
        let res = server.finalize();
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("'ip' is required"));
    }

    #[test]
    fn test_cors_wildcard_with_credentials_rejected() {
        let toml_str = r#"
            name = "cors_test"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = ["Cors"]

            [Layers.Cors]
            allowed_origins = ["*"]
            allow_credentials = true
            allowed_methods = ["GET"]
            allowed_headers = ["*"]
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        let res = server.finalize();
        assert!(res.is_err());
        let err_msg = format!("{:#}", res.unwrap_err());
        assert!(err_msg.contains("Cors") && err_msg.contains("allow_credentials"));
    }

    #[test]
    fn test_rate_limiter_zero_rps_rejected() {
        let toml_str = r#"
            name = "rate_limit_test"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = ["RateLimiter:Simple"]

            [Layers.RateLimiter]
            requests_per_second = 0
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        let res = server.finalize();
        assert!(res.is_err());
        let err_msg = format!("{:#}", res.unwrap_err());
        assert!(err_msg.contains("requests_per_second must be greater than 0"));
    }

    #[test]
    fn test_concurrency_limit_zero_rejected() {
        let toml_str = r#"
            name = "concurrency_test"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = ["ConcurrencyLimit"]

            [Layers.ConcurrencyLimit]
            max_concurrent_requests = 0
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        let res = server.finalize();
        assert!(res.is_err());
        let err_msg = format!("{:#}", res.unwrap_err());
        assert!(err_msg.contains("max_concurrent_requests must be greater than 0"));
    }

    #[test]
    fn test_router_params_defaults() {
        let toml_str = r#"
            protocol = "http"
        "#;
        let params: RouterParams = toml::from_str(toml_str).unwrap();
        assert_eq!(params.connect_timeout_seconds, 5);
        assert_eq!(params.request_timeout_seconds, 30);
        assert_eq!(params.idle_timeout_seconds, 90);
        assert_eq!(params.grpc_reflection_timeout_seconds, 10);
        assert_eq!(params.grpc_reflection_ttl_seconds, 600);
    }

    #[test]
    fn test_router_params_custom_timeouts() {
        let toml_str = r#"
            protocol = "https"
            connect_timeout_seconds = 2
            request_timeout_seconds = 15
            idle_timeout_seconds = 45
            grpc_reflection_timeout_seconds = 8
            grpc_reflection_ttl_seconds = 300
        "#;
        let params: RouterParams = toml::from_str(toml_str).unwrap();
        assert_eq!(params.connect_timeout_seconds, 2);
        assert_eq!(params.request_timeout_seconds, 15);
        assert_eq!(params.idle_timeout_seconds, 45);
        assert_eq!(params.grpc_reflection_timeout_seconds, 8);
        assert_eq!(params.grpc_reflection_ttl_seconds, 300);
    }

    #[test]
    fn test_connection_limits_defaults() {
        let toml_str = r#"
            name = "conn_limits_default"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = []
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(server.connection_limits.max_connections, 10_000);
        assert_eq!(server.connection_limits.max_connections_per_ip, 100);
        assert!(server.finalize().is_ok());
    }

    #[test]
    fn test_connection_limits_custom() {
        let toml_str = r#"
            name = "conn_limits_custom"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = []

            [connection_limits]
            max_connections = 500
            max_connections_per_ip = 25
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(server.connection_limits.max_connections, 500);
        assert_eq!(server.connection_limits.max_connections_per_ip, 25);
        assert!(server.finalize().is_ok());
    }

    #[test]
    fn test_connection_limits_zero_rejected() {
        let toml_str = r#"
            name = "conn_limits_zero"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = []

            [connection_limits]
            max_connections = 0
            max_connections_per_ip = 25
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        let res = server.finalize();
        assert!(res.is_err());
        assert!(format!("{:#}", res.unwrap_err()).contains("max_connections must be strictly greater than 0"));

        let toml_str_ip_zero = r#"
            name = "conn_limits_ip_zero"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = []

            [connection_limits]
            max_connections = 100
            max_connections_per_ip = 0
        "#;
        let mut server_ip_zero: ServerConfig = toml::from_str(toml_str_ip_zero).unwrap();
        let res_ip = server_ip_zero.finalize();
        assert!(res_ip.is_err());
        assert!(format!("{:#}", res_ip.unwrap_err()).contains("max_connections_per_ip must be strictly greater than 0"));
    }

    #[test]
    fn test_compiled_rbac_matching() {
        let toml_str = r#"
            name = "rbac_test_server"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = []

            [rbac]
            "/api/Admin*" = ["Admin"]
            "/api/AdminGetProducts" = ["Admin", "Seller"]
            "/api/GetDatabaseTables" = ["Admin"]
            "/api/Public*" = ["*"]
            "/api/Blocked" = []
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        assert!(server.finalize().is_ok());

        let compiled = server.compiled_rbac.as_ref().expect("compiled_rbac should be populated");

        // Exact match
        let tables_roles = compiled.match_path("/api/GetDatabaseTables").unwrap();
        assert_eq!(tables_roles, &[UserRole("Admin".to_string())]);

        // Exact match overrides prefix
        let products_roles = compiled.match_path("/api/AdminGetProducts").unwrap();
        assert_eq!(products_roles, &[UserRole("Admin".to_string()), UserRole("Seller".to_string())]);

        // Prefix match
        let delete_user_roles = compiled.match_path("/api/AdminDeleteUser").unwrap();
        assert_eq!(delete_user_roles, &[UserRole("Admin".to_string())]);

        // Wildcard role prefix
        let public_roles = compiled.match_path("/api/Public/hello").unwrap();
        assert_eq!(public_roles, &[UserRole("*".to_string())]);

        // Empty role list (blocked)
        let blocked_roles = compiled.match_path("/api/Blocked").unwrap();
        assert!(blocked_roles.is_empty());

        // Unmatched path
        assert!(compiled.match_path("/other/path").is_none());
    }

    #[test]
    fn test_upstream_node_mark_dead_and_is_available() {
        let node = UpstreamNode::new("http://127.0.0.1:8080".parse().unwrap());
        node.current_score
            .store(100, std::sync::atomic::Ordering::Relaxed);

        // 1. Initially alive
        assert!(node.is_available(10));

        // 2. Mark dead -> unavailable immediately
        node.mark_dead();
        assert!(!node.is_available(10));

        // 3. Manually reset last_failure_time to 0 while is_alive=false -> must still be unavailable!
        node.last_failure_time.store(0, std::sync::atomic::Ordering::Relaxed);
        assert!(!node.is_available(10));

        // 4. Simulate cooldown elapsed
        let past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - 15;
        node.last_failure_time.store(past, std::sync::atomic::Ordering::Relaxed);
        assert!(node.is_available(10)); // 15s > 10s cooldown -> now available for retry

        // 5. Recover node
        node.mark_alive();
        assert!(node.is_available(10));
        assert_eq!(node.last_failure_time.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn test_security_headers_outermost_positioning() {
        let custom_csp = "default-src 'self'; img-src 'self' data:".to_string();
        let layers_cfg = Layers {
            enabled: vec![
                "Logger".to_string(),
                "Inspection".to_string(),
                "ConcurrencyLimit".to_string(),
            ],
            security_headers_config: Some(SecurityHeadersConfig {
                content_security_policy: custom_csp.clone(),
                ..Default::default()
            }),
            concurrency_limit_config: Some(ConcurrencyLimitConfig {
                max_concurrent_requests: 100,
                load_shed: true,
                queue_timeout_ms: None,
            }),
            ..Default::default()
        };

        let layers = layers_cfg.build_middleware_layers("test_server").unwrap();
        // SecurityHeaders must be placed near the top (outermost) so it intercepts short-circuit responses
        // and must preserve custom [Server.Layers.SecurityHeaders] settings even if not in `enabled`.
        assert!(matches!(layers[0], MiddlewareLayer::Logger));
        match &layers[1] {
            MiddlewareLayer::SecurityHeaders(cfg) => {
                assert_eq!(cfg.content_security_policy, custom_csp);
            }
            other => panic!("Expected SecurityHeaders at index 1, got {:?}", other),
        }
        assert!(matches!(layers[2], MiddlewareLayer::Inspection));
        assert!(matches!(layers[3], MiddlewareLayer::ConcurrencyLimit(_)));
    }

    #[test]
    fn test_compiled_allowed_pathes_longest_prefix_and_methods() {
        let mut post_rules = HashMap::new();
        // Exact rule
        post_rules.insert(
            "/api/v2/special".to_string(),
            vec!["^/api/v2/special$".to_string()],
        );
        // More specific prefix rule
        post_rules.insert(
            "/api/v2/*".to_string(),
            vec!["^/api/v2/items/[0-9]+$".to_string()],
        );
        // Broader prefix rule
        post_rules.insert(
            "/api/*".to_string(),
            vec!["^/api/.*$".to_string()],
        );

        let mut get_rules = HashMap::new();
        get_rules.insert("/status".to_string(), vec!["^/status$".to_string()]);

        let mut patch_rules = HashMap::new();
        patch_rules.insert("/update".to_string(), vec!["^/update$".to_string()]);

        let mut head_rules = HashMap::new();
        head_rules.insert("/ping".to_string(), vec!["^/ping$".to_string()]);

        let raw = AllowedPathes {
            post: Some(post_rules),
            get: Some(get_rules),
            patch: Some(patch_rules),
            head: Some(head_rules),
            ..Default::default()
        };

        let compiled = CompiledAllowedPathes::from_raw(&raw).unwrap();

        // 1. Exact match
        assert!(compiled.is_allowed("POST", "/api/v2/special", ""));

        // 2. Longest prefix: /api/v2/items/123 matches /api/v2/*
        assert!(compiled.is_allowed("POST", "/api/v2/items/123", ""));

        // 3. /api/v1/other matches broader /api/*
        assert!(compiled.is_allowed("POST", "/api/v1/other", ""));

        // 4. /api/v2/letters doesn't match /api/v2/* pattern, but falls through to broader /api/*
        assert!(compiled.is_allowed("POST", "/api/v2/letters", ""));

        // 5. Unmatched path
        assert!(!compiled.is_allowed("POST", "/other", ""));

        // 6. PATCH support
        assert!(compiled.is_allowed("PATCH", "/update", ""));
        assert!(!compiled.is_allowed("PATCH", "/status", ""));

        // 7. Explicit HEAD support
        assert!(compiled.is_allowed("HEAD", "/ping", ""));

        // 8. HEAD fallback to GET (/status is in GET)
        assert!(compiled.is_allowed("HEAD", "/status", ""));

        // 9. OPTIONS matches if any method allows the path
        assert!(compiled.is_allowed("OPTIONS", "/status", ""));
        assert!(compiled.is_allowed("OPTIONS", "/update", ""));
        assert!(!compiled.is_allowed("OPTIONS", "/unregistered", ""));

        // 10. Unsupported method
        assert!(!compiled.is_allowed("TRACE", "/status", ""));
    }

    #[test]
    fn test_chatapp_admin_rbac_and_idp_allowed_pathes() {
        for config_path in [
            "../conf.d/01_chatapp.toml.template",
            "../conf.d/01_chatapp.toml.local.template",
            "../conf.d/01_chatapp.toml",
        ] {
            let toml_str = std::fs::read_to_string(config_path)
                .unwrap_or_else(|e| panic!("Failed to read {}: {}", config_path, e));
            let value: toml::Value = toml::from_str(&toml_str).unwrap();
            let servers_arr = value
                .get("Server")
                .and_then(|v| v.as_array())
                .expect("Expected [[Server]] array in config");

            let servers: Vec<ServerConfig> = servers_arr
                .iter()
                .map(|v| v.clone().try_into().expect("Failed to deserialize ServerConfig"))
                .collect();

            // 1. Verify wurzelwerk_admin RBAC rules
            let admin_srv = servers
                .iter()
                .find(|s| s.name == "wurzelwerk_admin")
                .expect("wurzelwerk_admin missing");
            let rbac = CompiledRbac::from_raw(admin_srv.rbac.as_ref().unwrap());

            let seller_allowed = [
                "/api/Logout",
                "/api/WhoAmI",
                "/api/GetAdminConversations",
                "/api/AdminGetMembers",
                "/api/GetAdminOrders",
                "/api/AdminUpdateOrderStatus",
                "/api/AdminGetProducts",
                "/api/AdminAddProduct",
                "/api/AdminDeleteProduct",
                "/api/AdminGetRides",
                "/api/AdminGetRideRequests",
                "/api/AdminGetRideBookings",
                "/api/AdminDeleteRide",
                "/api/AdminDeleteRideReq",
            ];
            for path in &seller_allowed {
                let roles = rbac.match_path(path).expect(path);
                assert!(
                    roles.contains(&UserRole("Seller".to_string())),
                    "Expected Seller to be allowed on {} in {}",
                    path,
                    config_path
                );
            }

            // Every other POST path in AllowedPathes must strictly require Admin only
            let admin_post_paths = admin_srv
                .allowed_pathes
                .as_ref()
                .unwrap()
                .post
                .as_ref()
                .unwrap();
            for path in admin_post_paths.keys() {
                if !seller_allowed.contains(&path.as_str()) {
                    let roles = rbac
                        .match_path(path)
                        .unwrap_or_else(|| panic!("Missing RBAC rule for {} in {}", path, config_path));
                    assert_eq!(
                        roles,
                        &[UserRole("Admin".to_string())],
                        "Endpoint {} must be restricted to Admin only in {}",
                        path,
                        config_path
                    );
                }
            }

            // 2. Verify wurzelwerk_idp AllowedPathes & Layers
            let idp_srv = servers
                .iter()
                .find(|s| s.name == "wurzelwerk_idp")
                .expect("wurzelwerk_idp missing");
            let idp_paths = CompiledAllowedPathes::from_raw(idp_srv.allowed_pathes.as_ref().unwrap()).unwrap();
            assert!(idp_paths.is_allowed("GET", "/.well-known/jwks.json", ""));
            assert!(idp_paths.is_allowed("GET", "/auth/login_page", "aud=admin-dashboard"));
            assert!(idp_paths.is_allowed("GET", "/auth/status", "session=abc_123&poll_secret=xyz-456"));
            assert!(idp_paths.is_allowed("POST", "/auth/login", "aud=admin-dashboard"));
            assert!(idp_paths.is_allowed("POST", "/auth/confirm", "session=abc_123&code=234-567"));
            assert!(idp_paths.is_allowed("POST", "/auth/revoke", ""));
            assert!(!idp_paths.is_allowed("GET", "/admin", ""));
        }
    }

    #[test]
    fn test_ip_filter_config_validation() {
        let valid_toml = r#"
            name = "ip_filter_valid"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = ["IpFilter"]

            [Layers.IpFilter]
            allow_cidrs = ["10.0.0.0/8", "127.0.0.1/32", "::1/128"]
            deny_cidrs = ["10.99.0.0/16"]
        "#;
        let mut srv_ok: ServerConfig = toml::from_str(valid_toml).unwrap();
        assert!(srv_ok.finalize().is_ok());

        let invalid_cidr_toml = r#"
            name = "ip_filter_invalid"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = ["IpFilter"]

            [Layers.IpFilter]
            allow_cidrs = ["10.0.0.0/99"]
        "#;
        let mut srv_bad: ServerConfig = toml::from_str(invalid_cidr_toml).unwrap();
        let res = srv_bad.finalize();
        assert!(res.is_err());
        assert!(format!("{:#}", res.unwrap_err()).contains("invalid allow_cidrs entry"));
    }

    #[test]
    fn test_aggregate_route_config_validation() {
        let valid_toml = r#"
            name = "agg_valid"
            enabled = true
            protocol = "http"
            service = "Router"
            ip = "127.0.0.1"
            port = 8080

            [RouterParams]
            protocol = "http"
            authentication = "None"

            [Layers]
            enabled = []

            [ReverseRoutes."/api/dashboard"]
            backend_type = "aggregate"
            allowed_roles = ["Admin"]

            [[ReverseRoutes."/api/dashboard".targets]]
            key = "user"
            backend_type = "grpc_transcoding"
            upstreams = ["127.0.0.1:50051"]
            path = "/user.UserService/GetUser"
            required = true

            [[ReverseRoutes."/api/dashboard".targets]]
            key = "notifications"
            backend_type = "rest"
            upstreams = ["http://127.0.0.1:8081"]
            path = "/v1/notifications"
            method = "GET"
            required = false
        "#;
        let mut srv_ok: ServerConfig = toml::from_str(valid_toml).unwrap();
        assert!(srv_ok.finalize().is_ok());
        assert_eq!(srv_ok.parsed_routes.len(), 1);
        let route = &srv_ok.parsed_routes[0];
        assert_eq!(route.backend_type, RouteBackendType::Aggregate);
        assert_eq!(route.aggregate_targets.len(), 2);
        assert_eq!(route.aggregate_targets[0].key, "user");
        assert!(route.aggregate_targets[0].required);
        assert_eq!(route.aggregate_targets[1].key, "notifications");
        assert!(!route.aggregate_targets[1].required);
        assert_eq!(
            route.aggregate_targets[1].method,
            Some(hyper::Method::GET)
        );

        let invalid_cases = [
            (
                "empty targets",
                r#"
                    [ReverseRoutes."/api/agg"]
                    backend_type = "aggregate"
                "#,
                "must define at least one target",
            ),
            (
                "reserved _errors key",
                r#"
                    [ReverseRoutes."/api/agg"]
                    backend_type = "aggregate"
                    [[ReverseRoutes."/api/agg".targets]]
                    key = "_errors"
                    upstreams = ["127.0.0.1:8081"]
                    path = "/v1/test"
                "#,
                "invalid target key",
            ),
            (
                "duplicate target key",
                r#"
                    [ReverseRoutes."/api/agg"]
                    backend_type = "aggregate"
                    [[ReverseRoutes."/api/agg".targets]]
                    key = "user"
                    upstreams = ["127.0.0.1:8081"]
                    path = "/v1/a"
                    [[ReverseRoutes."/api/agg".targets]]
                    key = "user"
                    upstreams = ["127.0.0.1:8082"]
                    path = "/v1/b"
                "#,
                "duplicate target key",
            ),
            (
                "invalid grpc path",
                r#"
                    [ReverseRoutes."/api/agg"]
                    backend_type = "aggregate"
                    [[ReverseRoutes."/api/agg".targets]]
                    key = "user"
                    backend_type = "grpc_transcoding"
                    upstreams = ["127.0.0.1:50051"]
                    path = "/OnlyService"
                "#,
                "must match '/<Package.Service>/<Method>'",
            ),
            (
                "non-POST grpc method",
                r#"
                    [ReverseRoutes."/api/agg"]
                    backend_type = "aggregate"
                    [[ReverseRoutes."/api/agg".targets]]
                    key = "user"
                    backend_type = "grpc_transcoding"
                    upstreams = ["127.0.0.1:50051"]
                    path = "/user.UserService/GetUser"
                    method = "GET"
                "#,
                "only supports POST method",
            ),
            (
                "targets on rest route",
                r#"
                    [ReverseRoutes."/api/agg"]
                    backend_type = "rest"
                    upstreams = ["127.0.0.1:8081"]
                    [[ReverseRoutes."/api/agg".targets]]
                    key = "user"
                    upstreams = ["127.0.0.1:8082"]
                    path = "/v1/a"
                "#,
                "only valid for backend_type = \"aggregate\"",
            ),
        ];

        for (label, route_toml, expected_err) in invalid_cases {
            let full_toml = format!(
                r#"
                    name = "agg_bad"
                    enabled = true
                    protocol = "http"
                    service = "Router"
                    ip = "127.0.0.1"
                    port = 8080
                    [RouterParams]
                    protocol = "http"
                    [Layers]
                    enabled = []
                    {route_toml}
                "#
            );
            let mut srv_bad: ServerConfig = toml::from_str(&full_toml).unwrap();
            let err = srv_bad.finalize().unwrap_err();
            let err_msg = format!("{:#}", err);
            assert!(
                err_msg.contains(expected_err),
                "Case '{label}' failed: expected '{expected_err}' in '{err_msg}'"
            );
        }
    }

    #[test]
    fn test_server_config_default_and_programmatic_finalize() {
        let mut empty_name = ServerConfig {
            ip: Some("127.0.0.1".into()),
            port: Some(8080),
            ..Default::default()
        };
        assert!(empty_name.finalize().is_err());

        let mut cfg = ServerConfig {
            name: "programmatic_test".into(),
            ip: Some("127.0.0.1".into()),
            port: Some(8080),
            ..Default::default()
        };
        assert!(cfg.enabled);
        assert!(cfg.finalize().is_ok());
        assert_eq!(cfg.static_name, Some("programmatic_test"));
    }

    #[test]
    fn test_per_server_pki_base_oid_override_and_global_fallback() {
        let dir = std::env::temp_dir().join(format!("praeco_oid_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let cfg_path = dir.join("Config.toml");
        std::fs::write(
            &cfg_path,
            r#"
pki_base_oid = "1.3.6.1.4.1.65111"

[[Server]]
name = "uses_global_fallback"
ip = "127.0.0.1"
port = 8080
[Server.Layers]
enabled = []

[[Server]]
name = "uses_server_override"
ip = "127.0.0.1"
port = 8081
pki_base_oid = "2.25.42"
[Server.Layers]
enabled = []
"#,
        )
        .expect("write Config.toml");

        let loaded = Config::load(cfg_path.to_str().unwrap()).expect("load config");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            loaded.parsed_pki_base_oid.as_deref(),
            Some(&[1, 3, 6, 1, 4, 1, 65111][..])
        );
        assert_eq!(
            loaded.servers[0].parsed_pki_base_oid.as_deref(),
            Some(&[1, 3, 6, 1, 4, 1, 65111][..])
        );
        assert_eq!(
            loaded.servers[1].parsed_pki_base_oid.as_deref(),
            Some(&[2, 25, 42][..])
        );

        let mut invalid = ServerConfig {
            name: "invalid_oid".into(),
            ip: Some("127.0.0.1".into()),
            port: Some(8082),
            pki_base_oid: Some("1.3.invalid.1".into()),
            ..Default::default()
        };
        assert!(invalid.finalize().is_err());
    }

    #[test]
    fn test_cors_credentials_rejects_wildcard_methods_and_headers() {
        let cases = [
            (
                "wildcard origin",
                vec!["*".into()],
                vec!["GET".into()],
                vec!["Content-Type".into()],
            ),
            (
                "wildcard method",
                vec!["https://example.com".into()],
                vec!["*".into()],
                vec!["Content-Type".into()],
            ),
            (
                "wildcard header",
                vec!["https://example.com".into()],
                vec!["GET".into()],
                vec!["*".into()],
            ),
        ];

        for (label, origins, methods, headers) in cases {
            let layers = Layers {
                enabled: vec!["Cors".into()],
                cors_config: Some(CorsConfig {
                    allowed_origins: origins,
                    allowed_methods: methods,
                    allowed_headers: headers,
                    allow_credentials: true,
                }),
                ..Default::default()
            };
            let err = layers
                .build_middleware_layers("cors_test")
                .expect_err(&format!("{label} with allow_credentials=true must fail"));
            assert!(
                err.to_string().contains("allow_credentials"),
                "Unexpected error for {label}: {err}"
            );
        }
    }

    #[test]
    fn test_jwt_layer_rejects_empty_issuer_and_audience() {
        let layers_empty_iss = Layers {
            enabled: vec!["JwtAuth".into()],
            jwt_config: Some(JwtAuthConfig {
                jwt_public_keys: vec!["dummy.pem".into()],
                cookie_fallback: None,
                redirect_on_failure: None,
                expected_issuer: "   ".into(),
                expected_audience: "api".into(),
                revoke_on_paths: vec![],
                require_jti: true,
                max_token_lifetime_seconds: common::DEFAULT_MAX_JWT_LIFETIME_SECS,
            }),
            ..Default::default()
        };
        assert!(layers_empty_iss
            .build_middleware_layers("jwt_iss_test")
            .is_err());

        let layers_empty_aud = Layers {
            enabled: vec!["JwtAuth".into()],
            jwt_config: Some(JwtAuthConfig {
                jwt_public_keys: vec!["dummy.pem".into()],
                cookie_fallback: None,
                redirect_on_failure: None,
                expected_issuer: "idp".into(),
                expected_audience: "".into(),
                revoke_on_paths: vec![],
                require_jti: true,
                max_token_lifetime_seconds: common::DEFAULT_MAX_JWT_LIFETIME_SECS,
            }),
            ..Default::default()
        };
        assert!(layers_empty_aud
            .build_middleware_layers("jwt_aud_test")
            .is_err());

        // Verify TOML defaults and explicit overrides for require_jti and max_token_lifetime_seconds
        let default_jwt_cfg: JwtAuthConfig = toml::from_str(
            r#"
            jwt_public_keys = ["k.pem"]
            expected_issuer = "idp"
            expected_audience = "api"
            "#,
        )
        .expect("default JwtAuthConfig TOML must parse");
        assert!(default_jwt_cfg.require_jti);
        assert_eq!(
            default_jwt_cfg.max_token_lifetime_seconds,
            common::DEFAULT_MAX_JWT_LIFETIME_SECS
        );

        let custom_jwt_cfg: JwtAuthConfig = toml::from_str(
            r#"
            jwt_public_keys = ["k.pem"]
            expected_issuer = "idp"
            expected_audience = "api"
            require_jti = false
            max_token_lifetime_seconds = 0
            "#,
        )
        .expect("custom JwtAuthConfig TOML must parse");
        assert!(!custom_jwt_cfg.require_jti);
        assert_eq!(custom_jwt_cfg.max_token_lifetime_seconds, 0);
    }

    #[test]
    fn test_config_rejects_unknown_fields_and_redacts_router_jwt_debug() {
        let bad_toml = r#"
[[Server]]
name = "typo_srv"
ip = "127.0.0.1"
port = 8080
protcol = "https"
[Server.Layers]
enabled = []
"#;
        let res: Result<Config, _> = toml::from_str(bad_toml);
        assert!(res.is_err(), "Unknown field 'protcol' must be rejected");

        let bad_idp_unknown = r#"
            name = "idp_unknown_field"
            ip = "127.0.0.1"
            port = 8080
            service = "Idp"
            [Layers]
            enabled = []
            [IdpParams]
            jwt_private_key = "priv.pem"
            on_webhok_failure = "reject"
        "#;
        assert!(
            toml::from_str::<ServerConfig>(bad_idp_unknown).is_err(),
            "Unknown field in [IdpParams] must be rejected"
        );

        let bad_webhook_policy = r#"
            name = "idp_bad_policy"
            ip = "127.0.0.1"
            port = 8080
            service = "Idp"
            [Layers]
            enabled = []
            [IdpParams]
            jwt_private_key = "priv.pem"
            on_webhook_failure = "fallback"
        "#;
        assert!(
            toml::from_str::<ServerConfig>(bad_webhook_policy).is_err(),
            "Typo in on_webhook_failure must be rejected by WebhookFailurePolicy"
        );

        let ok_idp_default: ServerConfig = toml::from_str(
            r#"
            name = "idp_default_policy"
            ip = "127.0.0.1"
            port = 8080
            service = "Idp"
            [Layers]
            enabled = []
            [IdpParams]
            jwt_private_key = "priv.pem"
        "#,
        )
        .unwrap();
        assert_eq!(
            ok_idp_default.idp_params.as_ref().unwrap().on_webhook_failure,
            WebhookFailurePolicy::Reject
        );

        let ok_idp_fallback: ServerConfig = toml::from_str(
            r#"
            name = "idp_fallback_policy"
            ip = "127.0.0.1"
            port = 8080
            service = "Idp"
            [Layers]
            enabled = []
            [IdpParams]
            jwt_private_key = "priv.pem"
            on_webhook_failure = "fallback_to_cert"
        "#,
        )
        .unwrap();
        assert_eq!(
            ok_idp_fallback.idp_params.as_ref().unwrap().on_webhook_failure,
            WebhookFailurePolicy::FallbackToCert
        );

        let rp = RouterParams {
            protocol: Protocol::Https,
            authentication: AuthenticationMethod::Jwt,
            ssl_root_certificate: None,
            jwt: Some("super-secret-jwt-token".into()),
            ssl_client_certificate: None,
            ssl_client_key: None,
            connect_timeout_seconds: 5,
            request_timeout_seconds: 30,
            idle_timeout_seconds: 90,
            grpc_reflection_timeout_seconds: 10,
            grpc_reflection_ttl_seconds: 600,
        };
        let dbg = format!("{rp:?}");
        assert!(!dbg.contains("super-secret-jwt-token"));
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn test_unauthenticated_admin_must_be_loopback_and_admin_route_requires_protection() {
        let mut non_loopback_admin = ServerConfig {
            name: "exposed_admin".into(),
            ip: Some("0.0.0.0".into()),
            port: Some(9090),
            service: ServiceType::Admin,
            authentication: AuthenticationMethod::None,
            ..Default::default()
        };
        assert!(
            non_loopback_admin.finalize().is_err(),
            "Unauthenticated Admin service on 0.0.0.0 must be rejected"
        );

        let mut loopback_admin = ServerConfig {
            name: "local_admin".into(),
            ip: Some("127.0.0.1".into()),
            port: Some(9090),
            service: ServiceType::Admin,
            authentication: AuthenticationMethod::None,
            ..Default::default()
        };
        assert!(
            loopback_admin.finalize().is_ok(),
            "Unauthenticated Admin service on 127.0.0.1 must be accepted (read-only monitoring)"
        );

        let unprotected_admin_route_toml = r#"
            name = "unprotected_admin_route"
            ip = "127.0.0.1"
            port = 8080
            service = "Router"
            authentication = "None"
            [Layers]
            enabled = []
            [ReverseRoutes."/admin"]
            backend_type = "admin"
        "#;
        let mut bad_router: ServerConfig = toml::from_str(unprotected_admin_route_toml).unwrap();
        assert!(
            bad_router.finalize().is_err(),
            "Route backend_type='admin' without auth/roles/rbac must be rejected"
        );
    }

    #[test]
    fn test_config_validation_rejects_contradictions_and_zero_tokio_threads() {
        let dir = std::env::temp_dir().join(format!(
            "praeco_cfg_contradictions_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("zero_threads.toml");
        std::fs::write(&cfg_path, "tokio_threads = 0\n").unwrap();
        let zero_res = Config::load(cfg_path.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            zero_res.is_err(),
            "tokio_threads = 0 must be rejected before Tokio Runtime::worker_threads(0) panics"
        );

        let pki = common::test_pki::TestPki::new();
        let ca_pem = common::test_pki::TestPki::s(&pki.relay_ca_pem);

        let http_mtls_toml = format!(
            r#"
            name = "http_mtls"
            ip = "127.0.0.1"
            port = 8080
            protocol = "http"
            authentication = "ClientCert"
            service = "Echo"
            [Layers]
            enabled = []
            [[client_certs]]
            ssl_client_ca = "{ca_pem}"
        "#
        );
        let mut http_mtls: ServerConfig = toml::from_str(&http_mtls_toml).unwrap();
        assert!(
            http_mtls.finalize().is_err(),
            "ClientCert on plain HTTP must be rejected"
        );

        let mut opt_http_mtls: ServerConfig =
            toml::from_str(&http_mtls_toml.replace("ClientCert", "OptionalClientCert")).unwrap();
        assert!(
            opt_http_mtls.finalize().is_err(),
            "OptionalClientCert on plain HTTP must be rejected"
        );

        let pub_pem = common::test_pki::TestPki::s(&pki.praeco_public_pem);
        let pub_key = common::test_pki::TestPki::s(&pki.praeco_public_key);
        let priv_key_dir = std::env::temp_dir().join(format!(
            "praeco_idp_host_domain_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&priv_key_dir).unwrap();
        let jwt_priv_path = priv_key_dir.join("jwt_priv.pem");
        std::fs::write(
            &jwt_priv_path,
            "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/IrnOV6maFjmtsjchLt6\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();

        let host_domain_toml = format!(
            r#"
            name = "idp_host_domain"
            ip = "127.0.0.1"
            port = 1339
            protocol = "https"
            service = "Idp"
            [Layers]
            enabled = []
            [server_certs]
            ssl_certificate = "{pub_pem}"
            ssl_certificate_key = "{pub_key}"
            [IdpParams]
            jwt_private_key = "{}"
            cookie_name = "__Host-jwt"
            cookie_domain = "example.test"
        "#,
            jwt_priv_path.display()
        );
        let mut bad_idp: ServerConfig = toml::from_str(&host_domain_toml).unwrap();
        let host_res = bad_idp.finalize();
        let _ = std::fs::remove_dir_all(&priv_key_dir);
        assert!(
            host_res.is_err(),
            "__Host- cookie paired with cookie_domain must be rejected in finalize()"
        );
    }

    #[test]
    fn test_route_header_policy_defaults_overrides_and_contradiction_checks() {
        let valid_toml = r#"
            name = "header_policy_router"
            ip = "127.0.0.1"
            port = 8080
            protocol = "http"
            service = "Router"
            [Layers]
            enabled = []
            [Layers.JWT]
            jwt_public_keys = []
            expected_issuer = "idp"
            expected_audience = "api"
            cookie_fallback = "admin-jwt"

            [ReverseRoutes."/default"]
            upstreams = ["http://127.0.0.1:9001"]

            [ReverseRoutes."/custom"]
            upstreams = ["http://127.0.0.1:9002"]
            forward_authorization = true
            strip_cookie_names = ["csrf_secret"]
            forward_headers = ["X-Request-Id", "Accept"]
        "#;
        let mut srv: ServerConfig = toml::from_str(valid_toml).unwrap();
        srv.finalize().unwrap();

        let default_route = srv
            .parsed_routes
            .iter()
            .find(|r| r.prefix == "/default")
            .unwrap();
        assert!(default_route.header_policy.strip_authorization);
        assert!(default_route.header_policy.strip_cookies);
        assert!(
            default_route
                .header_policy
                .strip_cookie_names
                .contains("admin-jwt")
        );
        assert!(default_route.header_policy.forward_headers.is_none());

        let custom_route = srv
            .parsed_routes
            .iter()
            .find(|r| r.prefix == "/custom")
            .unwrap();
        assert!(!custom_route.header_policy.strip_authorization);
        assert!(!custom_route.header_policy.strip_cookies);
        assert!(
            custom_route
                .header_policy
                .strip_cookie_names
                .contains("csrf_secret")
        );
        assert!(
            custom_route
                .header_policy
                .strip_cookie_names
                .contains("admin-jwt")
        );
        let allowlist = custom_route.header_policy.forward_headers.as_ref().unwrap();
        assert!(allowlist.contains("x-request-id"));
        assert!(allowlist.contains("accept"));

        let contradictory_auth = r#"
            name = "bad_auth"
            ip = "127.0.0.1"
            port = 8080
            service = "Router"
            [Layers]
            enabled = []
            [ReverseRoutes."/"]
            upstreams = ["http://127.0.0.1:9001"]
            strip_authorization = true
            forward_authorization = true
        "#;
        let mut s1: ServerConfig = toml::from_str(contradictory_auth).unwrap();
        assert!(s1.finalize().is_err());

        let contradictory_cookies = r#"
            name = "bad_cookies"
            ip = "127.0.0.1"
            port = 8080
            service = "Router"
            [Layers]
            enabled = []
            [ReverseRoutes."/"]
            upstreams = ["http://127.0.0.1:9001"]
            strip_cookies = true
            strip_cookie_names = ["sid"]
        "#;
        let mut s2: ServerConfig = toml::from_str(contradictory_cookies).unwrap();
        assert!(s2.finalize().is_err());

        let invalid_header_name = r#"
            name = "bad_hdr"
            ip = "127.0.0.1"
            port = 8080
            service = "Router"
            [Layers]
            enabled = []
            [ReverseRoutes."/"]
            upstreams = ["http://127.0.0.1:9001"]
            forward_headers = ["invalid header"]
        "#;
        let mut s3: ServerConfig = toml::from_str(invalid_header_name).unwrap();
        assert!(s3.finalize().is_err());
    }

    #[test]
    fn test_idp_cookie_domain_and_redirect_validation() {
        let base_params = |cookie_name: &str, cookie_domain: Option<&str>, redirect: &str| IdpParams {
            jwt_private_key: "priv.pem".to_string(),
            token_expiry_seconds: 900,
            session_ttl_seconds: 120,
            cookie_name: cookie_name.to_string(),
            cookie_domain: cookie_domain.map(ToString::to_string),
            redirect_after_login: redirect.to_string(),
            debug_show_session_id: None,
            issuer: "praeco-idp".to_string(),
            allowed_audiences: Vec::new(),
            jwt_public_key: None,
            claims_webhook_url: None,
            claims_webhook_timeout_ms: 3000,
            on_webhook_failure: WebhookFailurePolicy::Reject,
            claims_webhook_client_cert: None,
            claims_webhook_client_key: None,
            claims_webhook_ca_cert: None,
        };

        // Valid configurations
        assert!(validate_idp_cookie_and_redirect(&base_params("__Host-jwt", None, "/"), "idp").is_ok());
        assert!(
            validate_idp_cookie_and_redirect(
                &base_params("admin-jwt", Some("192.168.178.45"), "https://192.168.178.45:1338/admin"),
                "idp"
            )
            .is_ok()
        );
        assert!(
            validate_idp_cookie_and_redirect(
                &base_params("admin-jwt", Some(".example.com"), "/dashboard?tab=1"),
                "idp"
            )
            .is_ok()
        );

        // Invalid cookie names
        for bad_name in ["", "bad;name", "bad=name", "bad name", "bad\r\nname"] {
            assert!(
                validate_idp_cookie_and_redirect(&base_params(bad_name, None, "/"), "idp").is_err(),
                "cookie_name '{bad_name}' must be rejected"
            );
        }

        // Invalid cookie domains
        for bad_domain in ["", "evil.com; HttpOnly", "bad domain", "host\r\n", "-bad.example", "example."] {
            assert!(
                validate_idp_cookie_and_redirect(&base_params("admin-jwt", Some(bad_domain), "/"), "idp").is_err(),
                "cookie_domain '{bad_domain}' must be rejected"
            );
        }

        // Invalid redirect targets
        for bad_redirect in [
            "",
            "//evil.example/phish",
            "javascript:alert(1)",
            "data:text/html,<script>1</script>",
            "/admin\r\nX-Injected: 1",
            "/admin\\evil",
            "relative-without-slash",
        ] {
            assert!(
                validate_idp_cookie_and_redirect(&base_params("__Host-jwt", None, bad_redirect), "idp").is_err(),
                "redirect_after_login '{bad_redirect}' must be rejected"
            );
        }

        // End-to-end TOML -> ServerConfig::finalize() verification
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pki = common::test_pki::TestPki::new();
        let pub_pem = common::test_pki::TestPki::s(&pki.praeco_public_pem);
        let pub_key = common::test_pki::TestPki::s(&pki.praeco_public_key);
        let dir = std::env::temp_dir().join(format!("praeco_idp_toml_s07_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let jwt_priv_path = dir.join("jwt_priv.pem");
        std::fs::write(
            &jwt_priv_path,
            "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/IrnOV6maFjmtsjchLt6\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();

        let make_idp_toml = |extra: &str| {
            format!(
                r#"
                name = "idp_toml_s07"
                ip = "127.0.0.1"
                port = 1339
                protocol = "https"
                service = "Idp"
                [Layers]
                enabled = []
                [server_certs]
                ssl_certificate = "{pub_pem}"
                ssl_certificate_key = "{pub_key}"
                [IdpParams]
                jwt_private_key = "{}"
                {extra}
            "#,
                jwt_priv_path.display()
            )
        };

        let mut valid_srv: ServerConfig = toml::from_str(&make_idp_toml("")).unwrap();
        let valid_res = valid_srv.finalize();
        assert!(valid_res.is_ok(), "default IdP TOML config must finalize cleanly: {:?}", valid_res.err());

        let mut bad_cookie_srv: ServerConfig =
            toml::from_str(&make_idp_toml(r#"cookie_name = "bad;cookie""#)).unwrap();
        assert!(bad_cookie_srv.finalize().is_err());

        let mut bad_redirect_srv: ServerConfig =
            toml::from_str(&make_idp_toml(r#"redirect_after_login = "javascript:alert(1)""#)).unwrap();
        assert!(bad_redirect_srv.finalize().is_err());

        // P-07: mTLS with CRL rejects session_tickets = true in finalize()
        let ca_pem = common::test_pki::TestPki::s(&pki.relay_ca_pem);
        let crl_pem = common::test_pki::TestPki::s(&pki.relay_crl_pem);
        let mtls_ticket_toml = format!(
            r#"
            name = "mtls_crl_ticket_reject"
            ip = "127.0.0.1"
            port = 8443
            protocol = "https"
            authentication = "ClientCert"
            service = "Echo"
            [Layers]
            enabled = []
            [server_certs]
            ssl_certificate = "{pub_pem}"
            ssl_certificate_key = "{pub_key}"
            session_cache_size = 4096
            session_tickets = true
            [[client_certs]]
            ssl_client_ca = "{ca_pem}"
            ssl_client_crl = "{crl_pem}"
        "#
        );
        let mut bad_ticket_srv: ServerConfig = toml::from_str(&mtls_ticket_toml).unwrap();
        assert!(bad_ticket_srv.finalize().is_err());

        let mut ok_cache_srv: ServerConfig =
            toml::from_str(&mtls_ticket_toml.replace("session_tickets = true", "session_tickets = false")).unwrap();
        assert!(ok_cache_srv.finalize().is_ok());
        assert_eq!(
            ok_cache_srv.server_certs.as_ref().unwrap().session_cache_size,
            Some(4096)
        );

        // Q-08: Per-route retry_put_delete defaults to true and can be disabled per route
        let route_retry_toml = r#"
            name = "route_retry_opt_out"
            ip = "127.0.0.1"
            port = 8080
            protocol = "http"
            service = "Router"
            [Layers]
            enabled = []
            [ReverseRoutes."/default-idempotent"]
            upstreams = ["http://127.0.0.1:9001"]
            [ReverseRoutes."/non-idempotent"]
            upstreams = ["http://127.0.0.1:9002"]
            retry_put_delete = false
        "#;
        let mut retry_srv: ServerConfig = toml::from_str(route_retry_toml).unwrap();
        assert!(retry_srv.finalize().is_ok());
        let non_idem = retry_srv
            .parsed_routes
            .iter()
            .find(|r| r.prefix == "/non-idempotent")
            .unwrap();
        let default_idem = retry_srv
            .parsed_routes
            .iter()
            .find(|r| r.prefix == "/default-idempotent")
            .unwrap();
        assert!(!non_idem.retry_put_delete);
        assert!(default_idem.retry_put_delete);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_route_header_policy_preserves_cookie_fallback_when_all_cookies_forwarded(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let toml_str = r#"
            name = "cookie_passthrough_router"
            ip = "127.0.0.1"
            port = 8080
            protocol = "http"
            service = "Router"
            [Layers]
            enabled = []
            [Layers.JWT]
            jwt_public_keys = []
            expected_issuer = "praeco-idp"
            expected_audience = "admin-dashboard"
            cookie_fallback = "admin-jwt"

            [ReverseRoutes."/pass-all"]
            upstreams = ["http://127.0.0.1:9001"]
            strip_cookies = false

            [ReverseRoutes."/allowlist-cookie"]
            upstreams = ["http://127.0.0.1:9002"]
            forward_headers = ["Content-Type", "Cookie"]

            [ReverseRoutes."/selective-strip"]
            upstreams = ["http://127.0.0.1:9003"]
            strip_cookies = false
            strip_cookie_names = ["other_cookie"]
        "#;
        let mut srv: ServerConfig = toml::from_str(toml_str)?;
        srv.finalize()?;

        let pass_all = srv
            .parsed_routes
            .iter()
            .find(|r| r.prefix == "/pass-all")
            .ok_or("missing /pass-all route")?;
        assert!(!pass_all.header_policy.strip_cookies);
        assert!(pass_all.header_policy.strip_cookie_names.is_empty());

        let allowlist_cookie = srv
            .parsed_routes
            .iter()
            .find(|r| r.prefix == "/allowlist-cookie")
            .ok_or("missing /allowlist-cookie route")?;
        assert!(!allowlist_cookie.header_policy.strip_cookies);
        assert!(allowlist_cookie.header_policy.strip_cookie_names.is_empty());

        let selective = srv
            .parsed_routes
            .iter()
            .find(|r| r.prefix == "/selective-strip")
            .ok_or("missing /selective-strip route")?;
        assert!(!selective.header_policy.strip_cookies);
        assert!(selective.header_policy.strip_cookie_names.contains("other_cookie"));
        assert!(selective.header_policy.strip_cookie_names.contains("admin-jwt"));

        // Verify prepare_proxy_headers preserves admin-jwt on /pass-all
        let mut req_headers = hyper::HeaderMap::new();
        req_headers.insert(
            hyper::header::COOKIE,
            hyper::header::HeaderValue::from_static("admin-jwt=signed.jwt.token; theme=dark"),
        );
        let extensions = hyper::http::Extensions::new();
        crate::middleware::router::headers::prepare_proxy_headers(
            &mut req_headers,
            "cookie_passthrough_router",
            None,
            &extensions,
            &srv,
            &pass_all.header_policy,
        )
        .map_err(|_| "prepare_proxy_headers unexpectedly failed")?;

        let forwarded_cookie = req_headers
            .get(hyper::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .ok_or("Cookie header must be preserved when strip_cookies = false")?;
        assert!(forwarded_cookie.contains("admin-jwt=signed.jwt.token"));
        assert!(forwarded_cookie.contains("theme=dark"));
        Ok(())
    }

    #[test]
    fn test_finalize_counts_multi_crl_bundle_and_rejects_mixed_strict_crl()
    -> Result<(), Box<dyn std::error::Error>> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pki = common::test_pki::TestPki::new();
        let dir = pki
            .relay_crl_pem
            .parent()
            .ok_or("TestPki missing parent directory")?;
        let crl_bundle_path = dir.join("multi_crl_bundle.pem");
        let crl1 = std::fs::read_to_string(&pki.relay_crl_pem)?;
        let crl2 = std::fs::read_to_string(&pki.relay_crl_revoking_client_pem)?;
        std::fs::write(&crl_bundle_path, format!("{crl1}\n{crl2}"))?;

        let mut srv = ServerConfig {
            name: "multi_crl_finalize".into(),
            ip: Some("127.0.0.1".into()),
            port: Some(8443),
            protocol: Protocol::Https,
            authentication: AuthenticationMethod::ClientCert,
            server_certs: Some(ServerCertConfig {
                ssl_certificate: common::test_pki::TestPki::s(&pki.praeco_public_pem).to_string(),
                ssl_certificate_key: common::test_pki::TestPki::s(&pki.praeco_public_key)
                    .to_string(),
                ..Default::default()
            }),
            client_certs: Some(vec![ClientCertConfig {
                ssl_client_ca: common::test_pki::TestPki::s(&pki.relay_ca_pem).to_string(),
                ssl_client_crl: Some(crl_bundle_path.to_string_lossy().to_string()),
                strict_crl: true,
            }]),
            ..Default::default()
        };
        srv.finalize()?;
        assert_eq!(srv.pki_info.crl_revoked_certs_count, 2);
        assert!(srv.pki_info.crl_next_update_unix.is_some());

        // Mixing strict_crl = true and strict_crl = false on CRL-bearing client_certs must fail
        srv.client_certs = Some(vec![
            ClientCertConfig {
                ssl_client_ca: common::test_pki::TestPki::s(&pki.relay_ca_pem).to_string(),
                ssl_client_crl: Some(common::test_pki::TestPki::s(&pki.relay_crl_pem).to_string()),
                strict_crl: true,
            },
            ClientCertConfig {
                ssl_client_ca: common::test_pki::TestPki::s(&pki.public_ca_pem).to_string(),
                ssl_client_crl: Some(
                    common::test_pki::TestPki::s(&pki.relay_crl_revoking_client_pem).to_string(),
                ),
                strict_crl: false,
            },
        ]);
        assert!(srv.finalize().is_err());

        Ok(())
    }
