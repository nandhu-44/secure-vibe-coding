# Spring Boot secure baseline

```java
@Configuration
@EnableMethodSecurity
class SecurityConfig {
  @Bean
  SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
      .authorizeHttpRequests(a -> a
          .requestMatchers("/actuator/health", "/public/**").permitAll()
          .requestMatchers("/admin/**").hasRole("ADMIN")
          .anyRequest().authenticated())                                   // deny by default
      .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))           // verified JWT (issuer-uri configured)
      .headers(h -> h.contentSecurityPolicy(c -> c.policyDirectives("default-src 'self'; frame-ancestors 'none'"))
                     .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(63072000)))
      .cors(Customizer.withDefaults());                                      // CorsConfigurationSource bean with explicit origins
    // keep CSRF enabled for cookie/session auth; for stateless bearer-token APIs CSRF can be disabled deliberately
    return http.build();
  }
  @Bean PasswordEncoder passwordEncoder() { return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(); }
}

@GetMapping("/orders/{id}")
OrderDto get(@PathVariable UUID id, @AuthenticationPrincipal Jwt jwt) {
  return orders.findByIdAndOwnerId(id, jwt.getSubject())                 // object-level authz
               .map(OrderDto::from).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
}
```

## Pitfalls
- Bind requests to DTO records with `@Valid` constraints, never to JPA entities (mass assignment).
- JPQL/native queries: `:param` placeholders only. No string concatenation in `@Query` or `createQuery`.
- Actuator: expose only `health`/`info`. Secure the rest (`management.endpoints.web.exposure.include=health,info`).
- `server.error.include-stacktrace=never`, `include-message=never`.
- Deserialization: never enable Jackson default typing (`activateDefaultTyping`) on untrusted input. No `ObjectInputStream`.
- XML: `DocumentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.
- SpEL/OGNL: never evaluate user-provided expressions.
