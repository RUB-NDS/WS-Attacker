/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2011 Christian Mainka
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package wsattacker.plugin.signatureWrapping;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.WsdlSubmit;
import com.eviware.soapui.impl.wsdl.WsdlSubmitContext;

import com.eviware.soapui.impl.wsdl.support.soap.SoapUtils;
import com.eviware.soapui.model.iface.Request.SubmitException;
import java.io.File;
import java.util.List;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Document;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.main.composition.testsuite.RequestResponsePair;
import wsattacker.main.plugin.PluginState;
import wsattacker.main.testsuite.TestSuite;
import wsattacker.plugin.signatureWrapping.option.OptionManager;
import wsattacker.plugin.signatureWrapping.option.OptionPayload;
import wsattacker.plugin.signatureWrapping.option.OptionSchemaFiles;
import wsattacker.plugin.signatureWrapping.schema.NullSchemaAnalyzer;
import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzer;
import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzerInterface;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;
import static wsattacker.plugin.signatureWrapping.util.dom.DomUtilities.domToString;
import static wsattacker.plugin.signatureWrapping.util.dom.DomUtilities.showOnlyImportant;
import wsattacker.plugin.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.plugin.signatureWrapping.util.signature.SignatureManager;
import wsattacker.plugin.signatureWrapping.xpath.weakness.util.WeaknessLog;
import wsattacker.plugin.signatureWrapping.xpath.wrapping.WrappingOracle;

/**
 * This class integrates the XSW Plugin into the WS-Attacker framework.
 */
public class SignatureWrapping extends AbstractPlugin
{

  private static final long       serialVersionUID   = 1L;

  private SignatureManager        signatureManager;
  private OptionManager           optionManager;
  private SchemaAnalyzer          schemaAnalyser;
  private SchemaAnalyzerInterface usedSchemaAnalyser;

  int                             successThreashold  = 70;

  WsdlRequest                     attackRequest      = null;
  String                          originalSoapAction = null;

  /**
   * Initializes the XSW Plungin. Creates the SchemaAnalyzer, the SignatureManager and the OptionManger.
   */
  @Override
  public void initializePlugin()
  {
    this.schemaAnalyser = new SchemaAnalyzer();
    this.usedSchemaAnalyser = schemaAnalyser;
    this.signatureManager = new SignatureManager();
    this.optionManager = new OptionManager(this, signatureManager);
    Logger.getLogger("wsattacker.plugin.signatureWrapping").setLevel(Level.TRACE);
    Logger.getLogger("wsattacker.plugin.signatureWrapping.util").setLevel(Level.OFF);
    TestSuite.getInstance().getCurrentRequest().addCurrentRequestContentObserver(optionManager);
    addDefaultSchemas();
  }

  /**
   * Private function which adds default Schemea Files to the SchemaAnalyzer. Currently: SOAP 1.1, SOAP 1.2, XML DigSig,
   * WS-Addressing, WS-SecurityUtility and XPathFilter2
   */
  private void addDefaultSchemas()
  {
    // TODO: Find better way than hard-coding Schema names...
    final String schemaDir = "XML Schema";
    final String[] schemaFiles =
      {
          "ds.xsd", "soap11.xsd", "soap12.xsd", "wsa.xsd", "wssec-1.0.xsd", "wssec-1.1.xsd", "wsu.xsd", "xmldsig-filter2.xsd", "saml11.xsd", "saml20.xsd"
      };

    log().info("Adding Default Schemas: " + schemaFiles.toString());
    for (String cur : schemaFiles)
    {
      Document xsd;
      try
      {
        String filename = schemaDir + "/" + cur;
        log().info("Adding '" + filename + "'");
        xsd = DomUtilities.readDocument(getClass().getClassLoader().getResourceAsStream(filename));
      }
      catch (Exception e)
      {
        e.printStackTrace();
        System.err.println("Could not read: " + cur.toString());
        continue;
      }
      schemaAnalyser.appendSchema(xsd);
    }
  }

  /**
   * This is the attack implementation. Basically, it takes the original requests and asks the WrappingOracle for an XSW
   * message. All possibilities will be sent consecutively to the web service endpoint. The reply is then analyzed if
   * the attack was successful.
   */
  @Override
  protected void attackImplementationHook(RequestResponsePair original)
  {
    // save needed pointers
    attackRequest = original.getWsdlRequest().getOperation().addNewRequest(getName() + " ATTACK");

    // should the soapaction be changed?
    if (optionManager.getOptionSoapAction().getChoice() > 0)
    {
      originalSoapAction = attackRequest.getOperation().getAction();
      attackRequest.getOperation().setAction(optionManager.getOptionSoapAction().getValueAsString());
    }

    WrappingOracle wrappingOracle = new WrappingOracle(signatureManager.getDocument(), signatureManager.getPayloads(), usedSchemaAnalyser);

    int signedElements = wrappingOracle.getCountSignedElements();
    int elementsByID = wrappingOracle.getCountElementsReferedByID();
    int elementsByXPath = wrappingOracle.getCountElementsReferedByXPath();
    int elementsByFastXPath = wrappingOracle.getCountElementsReferedByFastXPath();
    int elementsByPrefixfreeTransformedFastXPath = wrappingOracle
        .getCountElementsReferedByPrefixfreeTransformedFastXPath();

    important(String
        .format("%d signed Elements:\n--> %d by ID\n--> %d by XPath\n  `--> %d by FastXPath\n  `--> %d by prefix free FastXPath (best)", signedElements, elementsByID, elementsByXPath, elementsByFastXPath, elementsByPrefixfreeTransformedFastXPath));

    // should the answer contain a specific string
    String searchString = optionManager.getOptionTheContainedString().getValue();
    boolean search = (!searchString.isEmpty() && optionManager.getOptionMustContainString().isOn());

    // start attacking
    int successCounter = 0;
    int max = wrappingOracle.maxPossibilities();
    Document attackDocument = null;
    info("Found " + max + " wrapping possibilites.");
    for (int i = 0; i < max; ++i)
    {
      info("Trying possibility " + (i + 1) + "/" + max);
      try
      {
        attackDocument = wrappingOracle.getPossibility(i);
      }
      catch (InvalidWeaknessException e)
      {
        log().warn("Could not abuse the weakness.");
// critical("Could not abuse the weakness.\n" + WeaknessLog.representation());
        e.printStackTrace();
        continue;
      }
      catch (Exception e)
      {
        log().error("Unknown error. " + e.getMessage());
// critical("Unknown error. " + e.getMessage() + "\n" + WeaknessLog.representation());
        e.printStackTrace();
        continue;
      }
// DomUtilities.writeDocument(attackDocument, String.format("/tmp/xsw/attack_%04d.xml", i+1), true);
      info(WeaknessLog.representation());
      String attackDocumentAsString = domToString(attackDocument);
      attackRequest.setRequestContent(attackDocumentAsString);

      WsdlSubmit<WsdlRequest> submit;
      try
      {
        submit = attackRequest.submit(new WsdlSubmitContext(attackRequest), false);
      }
      catch (SubmitException e)
      {
        log().warn("Could not submit the request. Trying next one.");
        e.printStackTrace();
        continue;
      }
      String responseContent = null;
      try {
         responseContent = submit.getResponse().getContentAsString();
      }
      catch (Exception e) {
        info("Error: " + e.getMessage());
        continue;
      }
      if (responseContent == null)
      {
        trace("Request:\n" + showOnlyImportant(submit.getRequest().getRequestContent()));
// trace("Request:\n" + (submit.getRequest().getRequestContent()));
        important("The server's answer was empty. Server misconfiguration?");
        continue;
      }
      try
      {
        if (SoapUtils.isSoapFault(responseContent, attackRequest.getOperation().getInterface().getSoapVersion()))
        {
          trace("Request:\n" + showOnlyImportant(submit.getRequest().getRequestContent()));
// trace("Request:\n" + (submit.getRequest().getRequestContent()));
          info("Server does not accept the message, you got a SOAP error.");
          trace("Response:\n" + showOnlyImportant(responseContent));
          continue;
        }
      }
      catch (XmlException e)
      {
        trace("Request:\n" + showOnlyImportant(submit.getRequest().getRequestContent()));
// trace("Request:\n" + (submit.getRequest().getRequestContent()));
        info("The answer is not valid XML. Server missconfiguration?");
        continue;
      }
      if (search)
      {
        int index = submit.getResponse().getContentAsString().indexOf(searchString);
        if (index < 0)
        {
          info("The answer does not contain the searchstring:\n" + searchString);
          continue;
        }
        else
        {
          important("The answer contains the searchstring:\n" + searchString);
        }
      }
      critical("Server Accepted the Request with Possibility " + (i + 1) + ".");
      important(String
          .format("Attack-Vector:\n\n%s\nRequest:\n%s", WeaknessLog.representation(), showOnlyImportant(submit
              .getRequest().getRequestContent())));
      info("Response:\n" + showOnlyImportant(responseContent));
      setCurrentPoints(getMaxPoints());
      ++successCounter;
      if (optionManager.getAbortOnFirstSuccess().isOn())
      {
        break;
      }
    }

    // Generate Result
    // ///////////////
    String message = "";
    if (getCurrentPoints() >= successThreashold)
    {
      message = "CRITICAL: Server could be successfully attacked!";
    }
    else if (signedElements == elementsByPrefixfreeTransformedFastXPath)
    {
      setCurrentPoints(0);
      message = "Everything is Okay: Server uses transformed prefix-free FastXPath. Best practices.";
    }
    else if (signedElements == elementsByFastXPath)
    {
      setCurrentPoints(10);
      message = "Good: Server uses FastXPath.";
    }
    else if (signedElements == elementsByXPath)
    {
      setCurrentPoints(20);
      message = "Okay: Server uses XPaths, but could not be successfully attacked.";
    }
    else if (elementsByXPath > 0 && elementsByID > 0)
    {
      setCurrentPoints(20);
      message = "Warning: Server uses ID References and XPaths mixed. Only XPaths are recommended.";
    }
    else if (signedElements == elementsByID)
    {
      setCurrentPoints(20);
      message = "Warning: Server uses ID References but could not be successfully attacked.";
    }

    // print result
    if (getCurrentPoints() < successThreashold)
      important(message);
    else
      critical(message);

    if (successCounter > 0 && !optionManager.getAbortOnFirstSuccess().isOn())
    {
      important(String.format("Found %d of %d working XSW messages.", successCounter, max));
    }

    removeAttackReqeust();
  }

  /**
   * The attack is only successful if the XSW message is accepted.
   */
  @Override
  public boolean wasSuccessful()
  {
    return isFinished() && getCurrentPoints() >= successThreashold;
  }

  /**
   * The maximum rating is 100. This is used to create a percent-rating.
   */
  @Override
  public int getMaxPoints()
  {
    return 100;
  }

  private void checkState()
  {
    // Change does not have payload -> Check if we have still *any* payload
    List<OptionPayload> list = signatureManager.getPayloads();
    if (list.size() < 1)
    {
      // No possible payloads found -> Request does not have a Signature
      setState(PluginState.Not_Configured);
    }
    else {
	for (OptionPayload payload : list)
	{
	  if (!payload.isTimestamp() && payload.hasPayload())
	  {
	    setState(PluginState.Ready);
	    return;
	  }
	}
    setState(PluginState.Not_Configured);
    }
  }

  /**
   * Observer fuction wich is called if an Option is changed.
   */
  @Override
  public void optionValueChanged(AbstractOption option)
  {
    if (option instanceof OptionPayload)
    {
      OptionPayload currentPayload = (OptionPayload) option;
      if (!currentPayload.isTimestamp() && currentPayload.hasPayload())
      {
        setState(PluginState.Ready);
        return;
      }
      checkState();
    }
    else if (option instanceof OptionSchemaFiles)
    {
      log().info("Cleared all Schemas");
      schemaAnalyser.clearSchemas();
      for (File f : ((OptionSchemaFiles) option).getFiles())
      {
        try
        {
          Document schema = DomUtilities.readDocument(f);
          log().info("Adding Schema " + f.getName());
          schemaAnalyser.appendSchema(schema);
        }
        catch (Exception e)
        {
          log().warn("Could not read Schema file '" + f.getName() + "'");
        }
      }
    }
    else if (option == optionManager.getOptionNoSchema())
    {
      if (optionManager.getOptionNoSchema().isOn())
        usedSchemaAnalyser = new NullSchemaAnalyzer();
      else
        usedSchemaAnalyser = schemaAnalyser;
    }
  }

  /**
   * Observer function which is called if the attack request is removed.
   */
  public void removeAttackReqeust()
  {

    if (originalSoapAction != null && attackRequest != null)
    {
      attackRequest.getOperation().setAction(originalSoapAction);
      originalSoapAction = null;
    }
    // remove attack request
    if (attackRequest != null)
    {
      attackRequest.getOperation().removeRequest(attackRequest);
      attackRequest = null;
    }
  }

  /**
   * Clean means to remove the attack request, set the current points to zero and check the plugin state.
   */
  @Override
  public void clean()
  {
    removeAttackReqeust();
    setCurrentPoints(0);
    checkState();
  }

  /**
   * If the plugin is stopped by user interaction, the attack request must be removed.
   */
  @Override
  public void stopHook()
  {
    removeAttackReqeust();
  }

  @Override
  public String getName()
  {
    return "Signature Wrapping";
  }

  @Override
  public String getAuthor()
  {
    return "Christian Mainka";
  }

  @Override
  public String getDescription()
  {
    StringBuffer desc = new StringBuffer();
    desc.append("Tries several XML Signature Wrapping techniques to invoke a Service with unsigned content.");
    desc.append("\n\nCurrently supported techniques:");
    desc.append("\n  (1) Attack ID References.");
    desc.append("\n  (2) Abuse descendant* Axis, e.g. double-slash in XPath.");
    desc.append("\n  (3) Abuse attribute expressions in XPaths.");
    desc.append("\n  (4) Try namespace-injection attack to attack prefixes in XPaths.");
// desc.append("\n\nThe Attack can use XML Schema files to reduces the number of tries (and so speed up the attack) by creating only Schema-Valid attack requests.");
// desc.append("\n\nIf some payload is marked as a timestamp, it will be updated and wrapped automatically.");
// desc.append("\n\nNote: In some cases, it makes sense to change the payload to a different operation.");
// desc.append("\nYou can also change the SoapActionHeader if you like.");
    desc.append("\n\n" + "At least one signed part needs some valid XML payload, otherwise the plugin is *not configured*.");
// desc.append("\n\nBy default, the attack is successfull if the response is not a SOAP Error.");
// desc.append("\nTo change this, a search string can be specified to ignore responses without this string.");
    return desc.toString();
  }

  @Override
  public String getVersion()
  {
    return "1.0 / 2012-03-30";
  }

  @Override
  public String[] getCategory()
  {
    return new String[]
      {
          "Security", "Signature"
      };
  }

  public SignatureManager getSignatureManager()
  {
    return signatureManager;
  }

  public SchemaAnalyzerInterface getUsedSchemaAnalyser()
  {
    return usedSchemaAnalyser;
  }

}
