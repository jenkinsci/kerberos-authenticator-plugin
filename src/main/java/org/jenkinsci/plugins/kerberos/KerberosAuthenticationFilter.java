package org.jenkinsci.plugins.kerberos;

import hudson.security.SecurityRealm;

import java.io.IOException;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

public class KerberosAuthenticationFilter implements Filter {

	public void destroy() {
		// TODO Auto-generated method stub

	}

	public void doFilter(ServletRequest servletRequest,
			ServletResponse servletResponse, FilterChain filterChain)
			throws IOException, ServletException {

		HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
		HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

		if (SecurityContextHolder.getContext().getAuthentication()!=null &&SecurityContextHolder.getContext().getAuthentication()
				.isAuthenticated()) {

			filterChain.doFilter(servletRequest, servletResponse);

		} else {

			LoginContext lc = null;

			try {
				lc = new LoginContext("Kerberos");

				lc.login();
				Subject subject = lc.getSubject();
				System.out.println(subject.toString());
				UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
						subject.getPrincipals().iterator().next(),
						subject.getPrivateCredentials().iterator()
								.next(),
						new GrantedAuthority[] { SecurityRealm.AUTHENTICATED_AUTHORITY });
				
				SecurityContextHolder.getContext().setAuthentication(token);
				
				filterChain.doFilter(servletRequest, servletResponse);
			} catch (LoginException le) {
				le.printStackTrace();
				httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN);

			}

		}

		/*
		 * 
		 * UsernamePasswordAuthenticationToken token = new
		 * UsernamePasswordAuthenticationToken( id.getEffectiveNick(), "",
		 * id.teams.toArray(new GrantedAuthority[id.teams.size()]));
		 * SecurityContextHolder.getContext().setAuthentication(token);
		 */

	}

	public void init(FilterConfig arg0) throws ServletException {

	}

}
