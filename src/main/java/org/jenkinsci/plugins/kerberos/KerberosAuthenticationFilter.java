package org.jenkinsci.plugins.kerberos;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sourceforge.spnego.SpnegoAuthenticator;
import net.sourceforge.spnego.SpnegoHttpFilter.Constants;
import net.sourceforge.spnego.SpnegoHttpServletResponse;
import net.sourceforge.spnego.SpnegoPrincipal;

import org.ietf.jgss.GSSException;

public class KerberosAuthenticationFilter implements Filter {
	
	private SpnegoAuthenticator authenticator;
	
	public KerberosAuthenticationFilter(SpnegoAuthenticator authenticator) {
		this.authenticator = authenticator;
	}
	
	public void destroy() {
		// TODO Auto-generated method stub

	}

	
	public void doFilter(ServletRequest request, ServletResponse response,FilterChain chain) throws IOException, ServletException {

		final HttpServletRequest httpRequest = (HttpServletRequest) request;
		final SpnegoHttpServletResponse spnegoResponse = new SpnegoHttpServletResponse(
				(HttpServletResponse) response);

		// client/caller principal
		final SpnegoPrincipal principal;
		try {
			principal = this.authenticator.authenticate(httpRequest,
					spnegoResponse);
		} catch (GSSException gsse) {
			System.out.println("HTTP Authorization Header="
					+ httpRequest.getHeader(Constants.AUTHZ_HEADER));
			throw new ServletException(gsse);
		}

		// context/auth loop not yet complete
		if (spnegoResponse.isStatusSet()) {
			return;
		}

		// assert
		if (null == principal) {
			System.out.println("Principal was null.");
			spnegoResponse.setStatus(
					HttpServletResponse.SC_INTERNAL_SERVER_ERROR, true);
			return;
		}

		System.out.println("principal=" + principal);

		chain.doFilter(httpRequest,
				response);
	}

	/*
	 * public void doFilter(ServletRequest servletRequest, ServletResponse
	 * servletResponse, FilterChain filterChain) throws IOException,
	 * ServletException {
	 * 
	 * HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
	 * HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
	 * 
	 * if (SecurityContextHolder.getContext().getAuthentication()!=null
	 * &&SecurityContextHolder.getContext().getAuthentication()
	 * .isAuthenticated() && !Functions.isAnonymous()) {
	 * 
	 * filterChain.doFilter(servletRequest, servletResponse);
	 * 
	 * } else {
	 * 
	 * LoginContext lc = null;
	 * 
	 * try { lc = new LoginContext("Kerberos");
	 * 
	 * lc.login(); Subject subject = lc.getSubject();
	 * System.out.println(subject.toString());
	 * UsernamePasswordAuthenticationToken token = new
	 * UsernamePasswordAuthenticationToken(
	 * subject.getPrincipals().iterator().next(),
	 * subject.getPrivateCredentials().iterator() .next(), new
	 * GrantedAuthority[] { SecurityRealm.AUTHENTICATED_AUTHORITY });
	 * 
	 * SecurityContextHolder.getContext().setAuthentication(token);
	 * 
	 * filterChain.doFilter(servletRequest, servletResponse); } catch
	 * (LoginException le) { le.printStackTrace();
	 * httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
	 * 
	 * }
	 * 
	 * } }
	 */

	/*
	 * 
	 * UsernamePasswordAuthenticationToken token = new
	 * UsernamePasswordAuthenticationToken( id.getEffectiveNick(), "",
	 * id.teams.toArray(new GrantedAuthority[id.teams.size()]));
	 * SecurityContextHolder.getContext().setAuthentication(token);
	 */

	public void init(FilterConfig arg0) throws ServletException {
		
	

	}

	

}
