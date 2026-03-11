# ─────────────────────────────────────────────────────────────────────────────
# CloudFront — CDN + DDoS protection (AWS Shield Standard included)
#
# Caches static assets and landing page. API requests pass through.
# Cost: $0 for first 1TB/mo transfer (free tier), then $0.085/GB.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_cloudfront_distribution" "main" {
  enabled             = true
  is_ipv6_enabled     = true
  http_version        = "http2and3"
  price_class         = "PriceClass_100" # US + Europe only (cheapest)
  comment             = "Sovereignly ${var.environment}"
  default_root_object = ""

  aliases = var.domain_name != "" ? [var.domain_name, "www.${var.domain_name}"] : []

  viewer_certificate {
    cloudfront_default_certificate = var.domain_name == "" ? true : false
    acm_certificate_arn            = var.domain_name != "" ? aws_acm_certificate.cloudfront[0].arn : null
    minimum_protocol_version       = "TLSv1.2_2021"
    ssl_support_method             = var.domain_name != "" ? "sni-only" : null
  }

  origin {
    domain_name = aws_lb.main.dns_name
    origin_id   = "alb"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = var.domain_name != "" ? "https-only" : "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "X-Forwarded-Host"
      value = var.domain_name != "" ? var.domain_name : aws_lb.main.dns_name
    }
  }

  # Default: pass everything to ALB (API requests, dashboard)
  default_cache_behavior {
    target_origin_id       = "alb"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    # No caching for API/dynamic content
    cache_policy_id          = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad" # CachingDisabled
    origin_request_policy_id = "216adef6-5c7f-47e4-b989-5492eafa07d3" # AllViewer
  }

  # Landing page: cache aggressively
  ordered_cache_behavior {
    path_pattern           = "/"
    target_origin_id       = "alb"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }

    min_ttl     = 0
    default_ttl = 300   # 5 minutes
    max_ttl     = 3600  # 1 hour
  }

  # Static assets: cache heavily
  ordered_cache_behavior {
    path_pattern           = "/_sovereign/static/*"
    target_origin_id       = "alb"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }

    min_ttl     = 86400     # 1 day
    default_ttl = 604800    # 7 days
    max_ttl     = 2592000   # 30 days
  }

  # Dashboard assets
  ordered_cache_behavior {
    path_pattern           = "/_sovereign/dashboard"
    target_origin_id       = "alb"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }

    min_ttl     = 0
    default_ttl = 60    # 1 minute
    max_ttl     = 300   # 5 minutes
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  tags = { Name = local.name }
}
