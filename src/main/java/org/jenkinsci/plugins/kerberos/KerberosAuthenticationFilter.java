package org.jenkinsci.plugins.kerberos;

import hudson.Functions;
import hudson.model.Hudson;
import hudson.security.SecurityRealm;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.PrivilegedActionException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.login.LoginException;
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

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.ietf.jgss.GSSException;

public class KerberosAuthenticationFilter implements Filter {

	private SpnegoAuthenticator authenticator;
	private String kdc;
	private String realm;

	private void initAuthenticator() {
		Map<String, String> props = new HashMap<String, String>();
		props.put("spnego.krb5.conf", Hudson.getInstance().getRootDir()
				.getPath()
				+ "/krb5.conf");

		props.put("spnego.login.conf", Hudson.getInstance().getRootDir()
				.getPath()
				+ "/jaas.conf");
		props.put(Constants.ALLOW_BASIC, "true");
		props.put("spnego.allow.localhost", "false");
		props.put("spnego.allow.unsecure.basic", "true");
		props.put("spnego.login.client.module", "spnego-client");
		props.put("spnego.krb5.conf", Hudson.getInstance().getRootDir()
				.getPath()
				+ "/krb5.conf");
		props.put("spnego.login.conf", Hudson.getInstance().getRootDir()
				.getPath()
				+ "/jaas.conf");
		props.put("spnego.preauth.username", "empty");
		props.put("spnego.preauth.password", "empty");
		props.put("spnego.login.server.module", "spnego-server");
		props.put("spnego.prompt.ntlm", "true");
		props.put("spnego.allow.delegation", "true");
		props.put("spnego.logger.level", "1");

		
		try {
			this.authenticator = new SpnegoAuthenticator(props);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public KerberosAuthenticationFilter() {

	}

	public void destroy() {
		// TODO Auto-generated method stub

	}

	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {

		if (SecurityContextHolder.getContext().getAuthentication() != null
				&& SecurityContextHolder.getContext().getAuthentication()
						.isAuthenticated() && !Functions.isAnonymous()) {

			chain.doFilter(request, response);
			return;

		}

		final HttpServletRequest httpRequest = (HttpServletRequest) request;
		final SpnegoHttpServletResponse spnegoResponse = new SpnegoHttpServletResponse(
				(HttpServletResponse) response);

		// client/caller principal
		SpnegoPrincipal principal = null;

		try {
			if (authenticator == null) {
				initAuthenticator();
			}
			principal = this.authenticator.authenticate(httpRequest,
					spnegoResponse);
		} catch (Exception e) {

			e.printStackTrace();
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

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
				principal.getName().split("@")[0],
				principal.getName().split("@")[0],
				new GrantedAuthority[] { SecurityRealm.AUTHENTICATED_AUTHORITY });

		SecurityContextHolder.getContext().setAuthentication(token);
		chain.doFilter(httpRequest, response);
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
