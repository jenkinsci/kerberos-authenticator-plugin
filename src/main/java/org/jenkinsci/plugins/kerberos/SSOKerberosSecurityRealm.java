package org.jenkinsci.plugins.kerberos;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import javax.servlet.ServletException;

import org.kohsuke.stapler.DataBoundConstructor;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.security.SecurityRealm;
import hudson.util.PluginServletFilter;

public class SSOKerberosSecurityRealm extends SecurityRealm{
	
	@DataBoundConstructor
	public SSOKerberosSecurityRealm(String kdc, String realm) {
		this.realm = realm;
		this.kdc = kdc;
		setUpKerberos();
		
		try {
			PluginServletFilter.addFilter(new KerberosAuthenticationFilter());
		} catch (ServletException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private String kdc;
	private String realm;
	
	@Override
	public SecurityComponents createSecurityComponents() {
		
		return new SecurityComponents();
	}
	
	
	private void setUpKerberos() {
		
		try {
			createConfigFiles();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.setProperty("java.security.krb5.realm", realm);
		System.setProperty("java.security.krb5.kdc", kdc);
		System.setProperty("http.auth.preference", "SSPI");
		System.setProperty("sun.security.krb5.debug", "true");
		System.setProperty("java.security.krb5.conf", Hudson.getInstance()
				.getRootDir().getPath()
				+ "/krb5.conf");
		System.setProperty("javax.security.auth.useSubjectCredsOnly", "true");
		System.setProperty("java.security.auth.login.config", Hudson
				.getInstance().getRootDir().getPath()
				+ "/jaas.conf");

	}

	private void createConfigFiles() throws IOException {
		// Jenkins will write new default kerberos config stuff, if they are not found on JENKINS_HOME
		
		// The admin have to make sure that useTicketCache=true
		
		File krbConf = new File(Hudson.getInstance().getRootDir().getPath()
				+ "/krb5.conf");
		
		
		if (!krbConf.exists()) {
			krbConf.createNewFile();

			FileWriter writer = new FileWriter(krbConf);
			writer.write("[libdefaults]\n");
			writer.write("default_tkt_enctypes = DES-CBC-CRC\n");
			writer.write("default_tgs_enctypes = DES-CBC-CRC\n");
			writer.write("permitted_enctypes = DES-CBC-CRC\n");
			writer.write("udp_preference_limit = 1\n");
			writer.write("[appdefaults]\n");
			writer.write("forwardable = true");
			writer.flush();
			writer.close();
		}
		
		File jaasConf = new File(Hudson.getInstance().getRootDir().getPath()
				+ "/jaas.conf");
		
		if (!jaasConf.exists()) {
			jaasConf.createNewFile();

			FileWriter writer = new FileWriter(jaasConf);
			writer.write("Kerberos {\n");
			writer.write("     com.sun.security.auth.module.Krb5LoginModule required\n");
			writer.write(" doNotPrompt=false useTicketCache=true useKeyTab=false;\n");
			writer.write("};");
			
			writer.flush();
			writer.close();
		}

	}

	public String getKdc() {
		return kdc;
	}

	public void setKdc(String kdc) {
		this.kdc = kdc;
	}

	public String getRealm() {
		return realm;
	}

	public void setRealm(String realm) {
		this.realm = realm;
	}
	
	@Extension
	public static class DescriptorImpl extends Descriptor<SecurityRealm> {

		@Override
		public String getDisplayName() {
			return "Kerberos SSO";
		}

	}
	
	

}
