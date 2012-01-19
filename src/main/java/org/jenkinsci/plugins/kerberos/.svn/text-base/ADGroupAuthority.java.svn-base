package org.jenkinsci.plugins.kerberos;

import org.acegisecurity.GrantedAuthority;

/**
 * Created by IntelliJ IDEA.
 * User: mbrunken
 * Date: 13.01.12
 * Time: 12:50
 * To change this template use File | Settings | File Templates.
 */
public class ADGroupAuthority implements GrantedAuthority {

    private final String group;

    public ADGroupAuthority(String group) {
        this.group = group;
    }

    public String getAuthority() {
        return group;  //
    }
}
