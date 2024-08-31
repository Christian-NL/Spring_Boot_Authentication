package authentication.testing.configs;

import authentication.testing.services.TokenBlacklistedService;
import authentication.testing.services.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final HandlerExceptionResolver handlerExceptionResolver;
    private final JwtService jwtService;
    private final TokenBlacklistedService tokenBlacklistedService;
    private final UserDetailsService userDetailsService;

    @Autowired
    public JwtAuthenticationFilter(
            JwtService jwtService,
            UserDetailsService userDetailsService,
            TokenBlacklistedService tokenBlacklistedService,
            HandlerExceptionResolver handlerExceptionResolver
    ) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.tokenBlacklistedService = tokenBlacklistedService;
        this.handlerExceptionResolver = handlerExceptionResolver;
    }

    /*@Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final  String authHeader = request.getHeader("Authorization");

        // Log the request path and authorization header
        System.out.println("Request Path: " + request.getServletPath());
        System.out.println("Authorization Header: " + authHeader);

        if (request.getServletPath().equals("/auth/signup") || request.getServletPath().equals("/auth/login")) {
            filterChain.doFilter(request, response);
            return;
        }

        if (authHeader == null || !authHeader.startsWith("Bearer")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            final String jwt = authHeader.substring(7);

            if (tokenBlacklistedService.isTokenBlaclisted(jwt)) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }

            if (jwtService.isTokenExpired(jwt)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Token is expired");
                return;
            }

            if (!jwtService.isValidFormat(jwt)) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.getWriter().write("Invalid token format");
                return;
            }

            final String userMail = jwtService.extractUsername(jwt);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (userMail != null && authentication == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userMail);

                if (jwtService.isTokenValid(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }

            }

            filterChain.doFilter(request, response);
        } catch (Exception exception) {
            handlerExceptionResolver.resolveException(request, response, null, exception);
        }
    } */

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        try {
            final String authHeader = request.getHeader("Authorization");

            // Log the request path and authorization header
            System.out.println("Request Path: " + request.getServletPath());
            System.out.println("Authorization Header: " + authHeader);

            if (request.getServletPath().equals("/auth/signup") ||
                    request.getServletPath().equals("/auth/login") ||
                    request.getServletPath().equals("/auth/refreshToken")) {
                filterChain.doFilter(request, response);
                return;
            }

            if (authHeader == null || !authHeader.startsWith("Bearer")) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Missing or invalid Authorization header");
                return;
            }

            final String jwt = authHeader.substring(7);


            if (jwt.isEmpty()) {
                throw new Exception("Token is missing or empty");
            }

            if (tokenBlacklistedService.isTokenBlaclisted(jwt)) {
                throw new Exception("Token is blacklisted");
            }

            if (jwtService.isTokenExpired(jwt)) {
                throw new Exception("Token is expired");
            }

            if (!jwtService.isValidFormat(jwt)) {
                throw new Exception("Invalid token format");
            }

            /*if (jwt.isEmpty()) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Token is missing or empty");
                return;
            }

            if (tokenBlacklistedService.isTokenBlaclisted(jwt)) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write("Token is blacklisted");
                return;
            }

            if (jwtService.isTokenExpired(jwt)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Token is expired");
                return;
            }

            if (!jwtService.isValidFormat(jwt)) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.getWriter().write("Invalid token format");
                return;
            }*/

            final String userMail = jwtService.extractUsername(jwt);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (userMail != null && authentication == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userMail);

                if (jwtService.isTokenValid(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }

            }

            filterChain.doFilter(request, response);
        } catch (Exception exception) {
            //handlerExceptionResolver.resolveException(request, response, null, exception);

            // Gérer toutes les exceptions ici

            String message = exception.getMessage();
            int statusCode;

            // Déterminer le statut HTTP en fonction du message d'exception
            if ("Missing or invalid Authorization header".equals(message)) {
                statusCode = HttpServletResponse.SC_UNAUTHORIZED;
            } else if ("Token is missing or empty".equals(message)) {
                statusCode = HttpServletResponse.SC_UNAUTHORIZED;
            } else if ("Token is blacklisted".equals(message)) {
                statusCode = HttpServletResponse.SC_BAD_REQUEST;
            } else if ("Token is expired".equals(message)) {
                statusCode = HttpServletResponse.SC_UNAUTHORIZED;
            } else if ("Invalid token format".equals(message)) {
                statusCode = HttpServletResponse.SC_FORBIDDEN;
            } else {
                // Pour toutes les autres exceptions
                statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
                message = "An unexpected error occurred.";
            }

            // Envoyer la réponse avec le code d'état approprié
            response.setStatus(statusCode);
            response.getWriter().write(message);

        }
    }

}
