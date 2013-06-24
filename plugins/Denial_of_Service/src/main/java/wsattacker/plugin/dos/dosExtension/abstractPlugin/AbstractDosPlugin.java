/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2012 Andreas Falkenberg
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package wsattacker.plugin.dos.dosExtension.abstractPlugin;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.support.types.StringToStringsMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.PluginFunctionInterface;
import wsattacker.main.composition.plugin.option.AbstractOptionInteger;
import wsattacker.main.composition.testsuite.RequestResponsePair;
import wsattacker.main.plugin.PluginState;
import wsattacker.main.plugin.option.OptionLimitedInteger;
import wsattacker.main.plugin.option.OptionSimpleBoolean;
import wsattacker.plugin.dos.dosExtension.function.postanalyze.DOSPostAnalyzeFunction;
import wsattacker.plugin.dos.dosExtension.mvc.AttackMVC;
import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;
import wsattacker.plugin.dos.dosExtension.option.OptionTextAreaSoapMessage;
import wsattacker.plugin.dos.dosExtension.option.OptionTextAreaSoapMessage.PayloadPosition;
import wsattacker.plugin.dos.dosExtension.requestSender.RequestObject;

/**
 * Abstract Plugin for DOS-Attacks!
 */
public abstract class AbstractDosPlugin extends AbstractPlugin {

    private static final long serialVersionUID = 1L;
    // DoS Plugin Options - Default
    private AbstractOptionInteger optionNumberThreads;
    private AbstractOptionInteger optionNumberRequests;
    private AbstractOptionInteger optionSecondsBetweenProbes;
    private AbstractOptionInteger optionSecondsBetweenRequests;
    private AbstractOptionInteger optionSecondsServerLoadRecovery;
    private OptionSimpleBoolean optionAutoFinalizeSwitch;
    private AbstractOptionInteger optionAutoFinalizeSeconds;
    private OptionSimpleBoolean optionNetworkTestEnabled;
    private AbstractOptionInteger optionNetworkTestNumberRequests;
    private AbstractOptionInteger optionNetworkTestRequestInterval;
    private OptionTextAreaSoapMessage optionTextAreaSoapMessage;
    // "Right-Click"-GUI List
    private List<PluginFunctionInterface> functionList;
    // Requests
    private RequestResponsePair originalRequestResponsePair;
    private Map<String, String> originalRequestHeaderFields;
    private RequestObject untamperedRequestObject;
    private RequestObject tamperedRequestObject;
    // DOS-attackModel
    private AttackModel attackModel;
    private boolean attackPrecheck = true; // Only if true GUI is started!

    /**
     * String of countermeasures
     */
    public String getCountermeasures() {
        return "";
    }

    /**
     * Checks if attack is possible with given original request
     */
    public boolean attackPrecheck() {
        return true;
    }

    @Override
    public void initializePlugin() {
        // PreInit Plugin
        preInitPlugin();

        // Custom user options added from attack class developer
        initializeDosPlugin();

        // Post Init
        postInitPlugin();
    }

    // Mandatory Init operations for DoS extesnion- Do NOT change!
    public void preInitPlugin() {
        // <editor-fold defaultstate="collapsed" desc="Attack Parameters - Should not be changed">
        // DOS Options - MANDATORY FOR DOS-PLUGIN TO WORK
        setOptionNumberThreads(new OptionLimitedInteger("Param 1", 2, "Number parallel attack threads", 0, 65536));
        setOptionNumberRequests(new OptionLimitedInteger("Param 2", 4, "Number requests per thread", 0, 65536));
        setOptionSecondsBetweenRequests(new OptionLimitedInteger("Param 3", 750, "Milliseconds between every attack request", 0, 65536));
        setOptionSecondsBetweenProbes(new OptionLimitedInteger("Param 4", 500, "Milliseconds between every testprobe request", 0, 65536));
        setOptionSecondsServerLoadRecovery(new OptionLimitedInteger("Param 5", 4, "Seconds server recovery time", 0, 65536));
        setOptionAutoFinalizeSwitch(new OptionSimpleBoolean("Param 6.0", true, "false = manuel stop, true = auto stop after defined sec after last tampered request"));
        setOptionAutoFinalizeSeconds(new OptionLimitedInteger("Param 6.1", 5, "seconds auto stop", 0, 655360));
        setOptionNetworkTestEnabled(new OptionSimpleBoolean("Param 7.0", false, "false = network stability test disabled, true = enabled"));
        setOptionNetworkTestNumberRequests(new OptionLimitedInteger("Param 7.1", 40, "Perform network stability test with defined number of requests", 0, 655360));
        setOptionNetworkTestRequestInterval(new OptionLimitedInteger("Param 7.2", 500, "ms between each Network Stability Testrequest", 0, 655360));
        getPluginOptions().add(getOptionNumberThreads());
        getPluginOptions().add(getOptionNumberRequests());
        getPluginOptions().add(getOptionSecondsBetweenProbes());
        getPluginOptions().add(getOptionSecondsBetweenRequests());
        getPluginOptions().add(getOptionSecondsServerLoadRecovery());
        getPluginOptions().add(getOptionAutoFinalizeSwitch());
        getPluginOptions().add(getOptionAutoFinalizeSeconds());
        getPluginOptions().add(getOptionNetworkTestEnabled());
        getPluginOptions().add(getOptionNetworkTestNumberRequests());
        getPluginOptions().add(getOptionNetworkTestRequestInterval());

        // Plugin Specific Options
        setState(PluginState.Ready);
        // </editor-fold>

        setFunctionList(new ArrayList<PluginFunctionInterface>());
        getFunctionList().add(new DOSPostAnalyzeFunction());
    }

    /*
     * Mandatory Init operations for DoS extension
     * In Order to insert a payload placeholer overwrite this method ans insert
     * value of enum PayloadPosition.
     */
    public void postInitPlugin() {
        // set payload position -> Always last option
        setOptionTextAreaSoapMessage(new OptionTextAreaSoapMessage("Message", "set position of payload placeholder", getPayloadPosition()));
        getPluginOptions().add(getOptionTextAreaSoapMessage());
    }

    /**
     * Initialization of DoS attack plugin by user
     */
    public abstract void initializeDosPlugin();

    /*
     * Get default payload position that will get inserted in original
     * SOAP message from SOAP test request
     */
    public abstract PayloadPosition getPayloadPosition();

    /**
     * Creates the final tampered (attack) request with payload
     */
    public abstract void createTamperedRequest();

    /*
     * Creates the final untampered request
     * Might get overwritten in special attack scenarious
     */
    public void createUntamperedRequest() {
        // Create clone of original Header
        Map<String, String> httpHeaderMap = new HashMap<String, String>();
        for (Map.Entry<String, String> entry : getOriginalRequestHeaderFields().entrySet()) {
            httpHeaderMap.put(entry.getKey(), entry.getValue());
        }
        // create Object
        this.setUntamperedRequestObject(httpHeaderMap, originalRequestResponsePair.getWsdlRequest().getEndpoint(), originalRequestResponsePair.getWsdlRequest().getRequestContent());
    }

    /*
     * Create Request Padding via appended long comment
     * Depending on size tampered OR untampered request is padded to size of
     * other
     * This way tampered and untampered Request always have same size and are
     * guranteed to cause same network load
     */
    public void createRequestPadding() {

        long sizeTamperedRequest = this.tamperedRequestObject.getXmlMessageLength();
        long sizeUntamperedRequest = this.untamperedRequestObject.getXmlMessageLength();
        long sizeDelta = sizeTamperedRequest - sizeUntamperedRequest;

        // padding for untampered request
        if (sizeDelta > 0) {

            StringBuilder sb = new StringBuilder();
            sb.append(this.untamperedRequestObject.getXmlMessage());

            sb.append("<!--");
            for (int i = 0; i < (sizeDelta - 7); i++) {
                sb.append("c");
            }
            sb.append("-->");

            this.untamperedRequestObject.setXmlMessage(sb.toString());
        }

        // padding for tampered request
        if (sizeDelta < 0) {
            StringBuilder sb = new StringBuilder();
            sb.append(tamperedRequestObject.getXmlMessage());

            sb.append("<!--");
            for (int i = 0; i < (Math.abs(sizeDelta) - 7); i++) {
                sb.append("c");
            }
            sb.append("-->");

            tamperedRequestObject.setXmlMessage(sb.toString());
        }
    }

    /**
     * get Original Request Headers
     * Method actually sends request and reads header fields
     */
    public void createOriginalRequestHeaderFields() {
        Map<String, String> httpHeaderMap = new HashMap();

        StringToStringsMap originalHeaders = originalRequestResponsePair.getWsdlResponse().getRequestHeaders();//response.getRequestHeaders();
        for (Map.Entry<String, List<String>> entry : originalHeaders.entrySet()) {
            for (String value : entry.getValue()) {
                httpHeaderMap.put(entry.getKey(), value);
            }
        }

        this.setOriginalRequestHeaderFields(httpHeaderMap);
    }

    /*
     * Performs the actual attack.
     * No need to override!
     * @param original
     */
    public void attackImplementationHook(RequestResponsePair original) {

        // save OriginalRequestResponsePair pointer
        originalRequestResponsePair = original;

        // save Original Header Fields for all subsequent requests
        createOriginalRequestHeaderFields();

        // check if attack is feasable with given original SOAP message
        if (attackPrecheck()) {

            // create the tampered and untampered request
            createTamperedRequest();
            createUntamperedRequest();

            // create Request Padding
            createRequestPadding();

            // perform DOS Attack
            // - returns ONLY if attackModel is in finished state!
            attackModel = AttackMVC.runDosAttack(this);

            // update PostAnalyze function with full model!
            DOSPostAnalyzeFunction b = (DOSPostAnalyzeFunction) functionList.get(0);
            b.setAttackModel(attackModel);

            // Set Attack Points
            setCurrentPoints(attackModel.getWsAttackerPoints());

            // Set Plugin State
            if (getCurrentPoints() == 0) {
                info(attackModel.getWsAttackerResults());
                setState(PluginState.Failed);
            } else if (getCurrentPoints() > 0) {
                important(attackModel.getWsAttackerResults());
                setState(PluginState.Finished);
            }
        } else {
            setCurrentPoints(0);
            important("Attack not possible - Structure of SOAP Message is not suitable!");
            setState(PluginState.Failed);
        }
    }

    @Override
    public int getMaxPoints() {
        return 100;
    }

    @Override
    public void clean() {
        attackModel = null;
        setCurrentPoints(0);
        setState(PluginState.Ready);

        // clean functionList with empty model!
        if (functionList.get(0) != null && functionList.get(0) instanceof DOSPostAnalyzeFunction) {
            DOSPostAnalyzeFunction b = (DOSPostAnalyzeFunction) functionList.get(0);
            b.setAttackModel(attackModel);
        }
    }

    @Override
    public void stopHook() {
        // restore possible data corruption
//	if (originalAction != null && originalRequest != null && !originalRequest.getOperation().getAction().equals(originalAction)) {
//	    originalRequest.getOperation().setAction(originalAction);
//	    originalRequest = null;
//	    originalAction = null;
//	}
        tamperedRequestObject = null;
        untamperedRequestObject = null;
    }

    @Override
    public boolean wasSuccessful() {
        // successfull only server is vulnerable for one method
        // note: one point = possible server misconfiguration
        return isFinished() && (getCurrentPoints() > 1);
    }

    @Override
    public String[] getCategory() {
        return new String[]{"Denial of Service"};
    }

    @Override
    public void restoreConfiguration(AbstractPlugin plugin) {
        /*
         * if (plugin instanceof CoersiveParsing) {
         * CoersiveParsing old = (CoersiveParsing) plugin;
         * // restore pluginOptions
         * // ...
         * }
         */
    }

    @Override
    public List<PluginFunctionInterface> getPluginFunctionList() {
        return functionList;
    }

    /**
     * ------------------------------------------
     * Getter and Setter
     * ------------------------------------------
     */
    public AbstractOptionInteger getOptionNumberThreads() {
        return optionNumberThreads;
    }

    public void setOptionNumberThreads(AbstractOptionInteger optionNumberThreads) {
        this.optionNumberThreads = optionNumberThreads;
    }

    public AbstractOptionInteger getOptionNumberRequests() {
        return optionNumberRequests;
    }

    public void setOptionNumberRequests(AbstractOptionInteger optionNumberRequests) {
        this.optionNumberRequests = optionNumberRequests;
    }

    public AbstractOptionInteger getOptionSecondsBetweenProbes() {
        return optionSecondsBetweenProbes;
    }

    public void setOptionSecondsBetweenProbes(AbstractOptionInteger optionSecondsBetweenProbes) {
        this.optionSecondsBetweenProbes = optionSecondsBetweenProbes;
    }

    public AbstractOptionInteger getOptionSecondsBetweenRequests() {
        return optionSecondsBetweenRequests;
    }

    public void setOptionSecondsBetweenRequests(AbstractOptionInteger optionSecondsBetweenRequests) {
        this.optionSecondsBetweenRequests = optionSecondsBetweenRequests;
    }

    public AbstractOptionInteger getOptionSecondsServerLoadRecovery() {
        return optionSecondsServerLoadRecovery;
    }

    public void setOptionSecondsServerLoadRecovery(AbstractOptionInteger optionSecondsServerLoadRecovery) {
        this.optionSecondsServerLoadRecovery = optionSecondsServerLoadRecovery;
    }

    public WsdlRequest getOriginalRequest() {
        return originalRequestResponsePair.getWsdlRequest();
    }

    public String getOriginalAction() {
        return originalRequestResponsePair.getWsdlRequest().getAction();
    }

    public AttackModel getAttackModel() {
        return attackModel;
    }

    public void setAttackModel(AttackModel attackModel) {
        this.attackModel = attackModel;
    }

    public boolean getAttackPrecheck() {
        return attackPrecheck;
    }

    public void setAttackPrecheck(boolean attackPrecheck) {
        this.attackPrecheck = attackPrecheck;
    }

    public OptionSimpleBoolean getOptionAutoFinalizeSwitch() {
        return optionAutoFinalizeSwitch;
    }

    public void setOptionAutoFinalizeSwitch(OptionSimpleBoolean optionAutoFinalizeSwitch) {
        this.optionAutoFinalizeSwitch = optionAutoFinalizeSwitch;
    }

    public AbstractOptionInteger getOptionAutoFinalizeSeconds() {
        return optionAutoFinalizeSeconds;
    }

    public void setOptionAutoFinalizeSeconds(AbstractOptionInteger optionAutoFinalizeSeconds) {
        this.optionAutoFinalizeSeconds = optionAutoFinalizeSeconds;
    }

    public List<PluginFunctionInterface> getFunctionList() {
        return functionList;
    }

    public void setFunctionList(List<PluginFunctionInterface> functionList) {
        this.functionList = functionList;
    }

    public OptionSimpleBoolean getOptionNetworkTestEnabled() {
        return optionNetworkTestEnabled;
    }

    public void setOptionNetworkTestEnabled(OptionSimpleBoolean optionNetworkTestEnabled) {
        this.optionNetworkTestEnabled = optionNetworkTestEnabled;
    }

    public AbstractOptionInteger getOptionNetworkTestNumberRequests() {
        return optionNetworkTestNumberRequests;
    }

    public void setOptionNetworkTestNumberRequests(AbstractOptionInteger optionNetworkTestNumberRequests) {
        this.optionNetworkTestNumberRequests = optionNetworkTestNumberRequests;
    }

    public AbstractOptionInteger getOptionNetworkTestRequestInterval() {
        return optionNetworkTestRequestInterval;
    }

    public void setOptionNetworkTestRequestInterval(AbstractOptionInteger optionNetworkTestRequestInterval) {
        this.optionNetworkTestRequestInterval = optionNetworkTestRequestInterval;
    }

    public RequestObject getTamperedRequestObject() {
        return tamperedRequestObject;
    }

    public void setTamperedRequestObject(Map<String, String> httpHeaderMap, String endpoint, String msg) {
        this.tamperedRequestObject = new RequestObject(msg, endpoint, httpHeaderMap);
    }

    public RequestObject getUntamperedRequestObject() {
        return untamperedRequestObject;
    }

    public void setUntamperedRequestObject(Map<String, String> httpHeaderMap, String endpoint, String msg) {
        this.untamperedRequestObject = new RequestObject(msg, endpoint, httpHeaderMap);
    }

    public OptionTextAreaSoapMessage getOptionTextAreaSoapMessage() {
        return optionTextAreaSoapMessage;
    }

    public void setOptionTextAreaSoapMessage(OptionTextAreaSoapMessage optionTextAreaSoapMessage) {
        this.optionTextAreaSoapMessage = optionTextAreaSoapMessage;
    }

    public Map<String, String> getOriginalRequestHeaderFields() {
        if (originalRequestHeaderFields == null) {
            originalRequestHeaderFields = new HashMap<String, String>();
        }
        return originalRequestHeaderFields;
    }

    public void setOriginalRequestHeaderFields(Map<String, String> originalRequestHeaderFields) {
        this.originalRequestHeaderFields = originalRequestHeaderFields;
    }

    public RequestResponsePair getOriginalRequestResponsePair() {
        return originalRequestResponsePair;
    }

    public void setOriginalRequestResponsePair(RequestResponsePair originalRequestResponsePair) {
        this.originalRequestResponsePair = originalRequestResponsePair;
    }
}
