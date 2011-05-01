package org.jenkinsci.plugins.kerberos;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class UserPasswordCallBackHandler implements CallbackHandler {

    /**
     * The username to be provided when prompted.
     */
    private String username;

    /**
     * The password to be provided when prompted.
     */
    private String password;

    /**
     * Create a new NamePasswordCallbackHandler (required Cams default
     * constructor that is dynamically called by the authentication server).
     */
    public UserPasswordCallBackHandler() {
        this.username = null;
        this.password = null;
    }

    /**
     * Create a new NamePasswordCallbackHandler (optional constructor used to
     * facilitate testing).
     * 
     * @param username
     *            the username to provide when prompted.
     * @param password
     *            the password to provide when prompted.
     */
    public UserPasswordCallBackHandler(String username, String password) {
        this.username = username;
        this.password = password;
    }

    /**
     * Set the username.
     * 
     * @param username
     *            the username to be provided to a NameCallback.
     */
    public void setUsername(String username) {
        if (username == null) {
            this.username = "";
            return;
        }

        this.username = username;
    }

    /**
     * Set the password.
     * 
     * @param password
     *            the password to be provided to a PasswordCallback.
     */
    public void setPassword(String password) {
        if (password == null) {
            this.password = "";
            return;
        }

        this.password = password;
    }

    /**
     * Retrieve or display the information requested in the provided Callbacks.
     * The handle method implementation checks the instance(s) of the Callback
     * object(s) passed in to retrieve or display the requested information.
     * 
     * @param callbacks
     *            an array of Callback objects provided by an underlying
     *            security service which contains the information requested to
     *            be retrieved or displayed.
     * 
     * @exception IOException
     *                if an input or output error ocurrs
     * @exception UnsupportedCallbackException
     *                if the implementation of this method does not support one
     *                or more of the Callbacks specified in the callbacks
     *                parameter
     */
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        // Loop over all Callbacks
        for (int i = 0; i < callbacks.length; i++) {
            Callback cb = callbacks[i];

            if (cb instanceof NameCallback) {
                ((NameCallback) cb).setName(username);
            } else if (cb instanceof PasswordCallback) {
                // JAAS specifies that the password is a char[]
                ((PasswordCallback) cb).setPassword(password.toCharArray());
            } else {
                throw new UnsupportedCallbackException(cb, "Unrecognized Callback");
            }
        }
    }

}
