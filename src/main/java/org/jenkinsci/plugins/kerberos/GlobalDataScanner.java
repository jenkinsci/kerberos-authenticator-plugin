package org.jenkinsci.plugins.kerberos;

import org.codehaus.jackson.map.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.*;


//Got from Sebastians with a few modifications

public class GlobalDataScanner {


    private static GlobalDataScanner instance;


    public static GlobalDataScanner getInstance() {
        if (instance == null) {
            instance = new GlobalDataScanner();
        }
        return instance;
    }

    private GlobalDataScanner() {

    }

    protected ProcessBuilder processBuilder;

    @SuppressWarnings("unchecked")
    public List<String> getUserGroups(String user) throws IOException {
        String osName = System.getProperty("os.name");
        if (!(osName.indexOf("nix") >= 0 || osName.indexOf("nux") >= 0)) {
            throw new IllegalStateException("Access to GlobalData only on Bigpoint *nix machines");
        }
        StringBuilder runArgument = new StringBuilder(
                "include(\"/usr/lib/cfg-permissions/permissions.inc.php\"); echo(json_encode(permissions::search_groups(\"" + user + "\")));");

        ArrayList<String> commandElements = new ArrayList<String>();
        commandElements.add("php");
        commandElements.add("-r");

        commandElements.add(runArgument.toString());

        String reply = runCommand(commandElements, 3000);
        ObjectMapper mapper = new ObjectMapper();
        List<String> list = mapper.readValue(reply, List.class);


        return list;
    }

    /**
     * Runs a native executable command with the given arguments by using a
     * ProcessBuilder. This is wrapped internally by a new thread to allow a
     * timeout. When the timeout is reached, the process is killed and the
     * function returns
     *
     * @param elements      A List of Strings. The first element is the executable, the
     *                      following elements are the arguments
     * @param timeoutMillis The timeout in milliseconds. If the timeout is hit, the
     *                      command is killed.
     * @return A String filled with the command line output of the command
     * @throws IOException if an I/O error occurs
     */
    protected String runCommand(final List<String> elements, long timeoutMillis) throws IOException {

        final StringBuilder sb = new StringBuilder();

        final ProcessBuilder pb = new ProcessBuilder(elements);
        pb.redirectErrorStream(true);
        final Process process = pb.start();

        Thread cmdExecutionThread = new Thread(new Runnable() {
            public void run() {
                InputStream is = null;
                InputStreamReader isr = null;
                BufferedReader br = null;
                try {
                    is = process.getInputStream();
                    isr = new InputStreamReader(is);
                    br = new BufferedReader(isr);
                    String line;
                    try {
                        while ((line = br.readLine()) != null) {
                            sb.append(line);
                            sb.append("\n");
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                } finally {
                    if (br != null) {
                        try {
                            br.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                    if (isr != null) {
                        try {
                            isr.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                    if (is != null) {
                        try {
                            is.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                    if (process != null) {
                        process.destroy();
                    }
                }
            }
        });
        cmdExecutionThread.start();
        try {
            cmdExecutionThread.join(timeoutMillis);
            process.destroy();
            process.waitFor();
        } catch (InterruptedException e) {
            e.printStackTrace();
            Thread.currentThread().interrupt();
        }
        return sb.toString();
    }
}
