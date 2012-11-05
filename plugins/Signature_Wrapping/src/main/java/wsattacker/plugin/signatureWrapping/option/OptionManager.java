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
package wsattacker.plugin.signatureWrapping.option;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.PluginOptionValueObserver;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.main.composition.testsuite.CurrentRequestContentChangeObserver;
import wsattacker.main.plugin.PluginOptionContainer;
import wsattacker.main.plugin.option.OptionSimpleBoolean;
import wsattacker.main.plugin.option.OptionSimpleChoice;
import wsattacker.main.plugin.option.OptionSimpleVarchar;
import wsattacker.plugin.signatureWrapping.SignatureWrapping;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;
import wsattacker.plugin.signatureWrapping.util.signature.SignatureManager;

/**
 * This class takes care on the options for the WS-Attacker XSW Plugin.
 */
public class OptionManager implements CurrentRequestContentChangeObserver, PluginOptionValueObserver
{

  private SignatureWrapping   plugin;
  private SignatureManager    signatureManager;
  private OptionSoapAction    optionSoapAction;
  private OptionSimpleBoolean optionMustContainString, optionNoSchema, abortOnFirstSuccess;
  private OptionSimpleVarchar optionTheContainedString;
  private OptionSchemaFiles   optionSchemaFiles;
  private OptionSimpleChoice  optionChoice;
  private OptionViewButton    optionView;

  private List<OptionPayload> payloadList;
  private OptionPayload       currentOptionPayload = null;

  private boolean             working              = false;

  /**
   * Initialization method.
   * @param plugin
   * @param signatureManager
   */
  public OptionManager(SignatureWrapping plugin,
                       SignatureManager signatureManager)
  {
    this.plugin = plugin;
    this.signatureManager = signatureManager;
    this.optionSoapAction = new OptionSoapAction("Change\nAction?", "Allows to change the SoapAction Header.");
    this.optionSchemaFiles = new OptionSchemaFiles();
    this.optionMustContainString = new OptionSimpleBoolean("Search?", false, "SOAP Response must contain a specific String.");
    this.abortOnFirstSuccess = new OptionSimpleBoolean("Abort?", true, "Abort after first successful attack message.");
    this.optionTheContainedString = new OptionSimpleVarchar("Contains", "Search for this String...", 200);
    this.optionNoSchema = new OptionSimpleBoolean("Schema?", false, "Turn on, to not use any XML Schema.");
    this.payloadList = new ArrayList<OptionPayload>();
    plugin.getPluginOptions().addPluginValueContainerObserver(this);
    this.optionView = new OptionViewButton();
  }

  private Logger log()
  {
    return Logger.getLogger(getClass());
  }

  /**
   * If the current request is changed, the SignatureManger must be notified.
   */
  @Override
  public void currentRequestContentChanged(String newContent,
                                           String oldContent)
  {
    if (!working) {
	working = true;
	log().trace("Current Request Content Changed");
	Document domDoc;
	try
	{
	  domDoc = DomUtilities.stringToDom(newContent);
	}
	catch (SAXException e)
	{
	  signatureManager.setDocument(null);
	  working = false;
	  return;
	}
	signatureManager.setDocument(domDoc);
	payloadList = signatureManager.getPayloads();
	List<String> choiceList = new ArrayList<String>();
	for (int i = 1; i <= payloadList.size(); ++i)
	  choiceList.add("Payload #" + i);
	log().info("Adding Choices: " + choiceList.toString());
	optionChoice = new OptionSimpleChoice("Show", choiceList, 0);
	working = false;
	addConfigOptions();
    }
  }

  /**
   * If no curent request is available, the SignatureManager must be notified.
   */
  @Override
  public void noCurrentRequestontent()
  {
    if (working) {
		  return;
	  }
    working = true;
    log().trace("No Current Message");
    signatureManager.setDocument(null);
    clearOptions();
    working = false;
  }

  /**
   * This methods add the default config options to the OptionManager.
   * Those are:
   *   - Option for changing the SOAPAction.
   *   - Option for aborting the attack if one XSW message is accepted.
   *   - Option to not use any XML Schema.
   *   - Option to selected XML Schema files.
   *   - Option to add a search string.
   *   - The View Button
   *   - The Payload-Chooser Combobox
   */
  public void addConfigOptions()
  {
    clearOptions();
    log().info("Adding SoapAction, SchemaFiles and MustContainString");
    PluginOptionContainer container = plugin.getPluginOptions();
    container.add(optionSoapAction);
    container.add(abortOnFirstSuccess);
    container.add(optionNoSchema);
    container.add(optionSchemaFiles);
    container.add(optionMustContainString);
    if (optionMustContainString.isOn())
    {
      container.add(optionTheContainedString);
    }
    if (optionChoice.getChoices().size() > 0)
    {
      log().info("Adding View Button");
      container.add(optionView);
      log().info(".. and added optionChoice");
      container.add(optionChoice);
      optionValueChanged(optionChoice);
    }

  }

  /**
   * This function is only needed due to a GUI Bug in WS-Attacker which
   * does not allow to put an AbstractOption at a specific position.
   * With this function, you can pop AbstractOptions up to one specific
   * one, than add the needed Options, and afterwards re-add the popped
   * one putOptions.
   * @param needle
   * @return
   */
  public List<AbstractOption> popOptionsUpTo(AbstractOption needle) {
    List<AbstractOption> result = new ArrayList<AbstractOption>();
    PluginOptionContainer container = plugin.getPluginOptions();
    if (!container.contains(needle)) {
		  return result;
	  }
    while(container.size() > 0) {
      AbstractOption last = container.getByIndex(container.size()-1);
      if (last == needle) {
		    break;
	    }
      container.remove(last);
      result.add(last);
    }
    log().info("Popped: " + result.toString());
    return result;
  }

  /**
   * This function is only needed due to a GUI Bug in WS-Attacker which
   * does not allow to put an AbstractOption at a specific position.
   * With this function, you can pop AbstractOptions up to one specific
   * one, than add the needed Options, and afterwards re-add the popped
   * one putOptions.
   * @param needle
   * @return
   */
  public void putOptions(List<AbstractOption> optionList) {
    log().info("Put: " + optionList.toString());
    PluginOptionContainer container = plugin.getPluginOptions();
    for(int i=optionList.size()-1; i >= 0; --i)
      container.add(optionList.get(i));
  }

  /**
   * Clear all options consecutively.
   */
  public void clearOptions()
  {
    log().info("Clearing Options..");
    PluginOptionContainer container = plugin.getPluginOptions();
    while (container.size() > 0)
      container.remove(container.getByIndex(0));
  }

  /**
   * Handler if an option value is changed.
   * Changes, e.g. the concrete showed PayloadOption.
   */
  @Override
  public void optionValueChanged(AbstractOption option)
  {
    log().info("Option Value Changed!");
    if (!working) {
	working = true;
	PluginOptionContainer container = plugin.getPluginOptions();
	if (option == optionChoice && optionChoice.getChoice() < payloadList.size())
	{
	  OptionPayload newOptionPayload = payloadList.get(optionChoice.getChoice());
	  if (newOptionPayload == currentOptionPayload)
	  {
	    log().info("New OptionPayload == Current OptionPayload -> Skipping");
	    return;
	  }
	  if (currentOptionPayload != null)
	  {
	    log().info("Removing old OptionPayload");
	    container.remove(currentOptionPayload);
	  }
	  log().info("Adding new payload" + payloadList.get(optionChoice.getChoice()).getName());
	  currentOptionPayload = newOptionPayload;
	  container.add(newOptionPayload);
	}
	else if (option == optionMustContainString)
	{
	  log().info("option == optionMustContainString");
	  if (optionMustContainString.isOn() && !container.contains(optionTheContainedString))
	  {
	    log().info("true == optionMustContainString.isOn()");
    //        List<AbstractOption> pop = popOptionsUpTo(optionMustContainString);
    //        container.add(optionTheContainedString);
    //        putOptions(pop);
	    container.add(1+container.indexOf(optionMustContainString), optionTheContainedString);
	  }
	  else if (container.contains(optionTheContainedString))
	  {
	    log().info("false == optionMustContainString.isOn()");
	    container.remove(optionTheContainedString);
	  }
	}
	else if (option == optionNoSchema)
	{
	  log().info("Remove Schema Files Option");
	  if (optionNoSchema.isOn() && container.contains(optionSchemaFiles))
	  {
	    container.remove(optionSchemaFiles);
	  }
	  else if (!container.contains(optionSchemaFiles))
	  {

	    log().info("Add Schema Files Option");
    //        List<AbstractOption> pop = popOptionsUpTo(optionNoSchema);
    //        container.add(optionSchemaFiles);
    //        putOptions(pop);
	    container.add(1+container.indexOf(optionNoSchema), optionSchemaFiles);
	  }
	}
	plugin.checkState();
	working = false;
    }
  }

  public OptionSoapAction getOptionSoapAction()
  {
    return optionSoapAction;
  }

  public OptionSchemaFiles getOptionSchemaFiles()
  {
    return optionSchemaFiles;
  }

  public OptionSimpleBoolean getOptionMustContainString()
  {
    return optionMustContainString;
  }

  public OptionSimpleBoolean getOptionNoSchema()
  {
    return optionNoSchema;
  }

  public OptionSimpleBoolean getAbortOnFirstSuccess()
  {
    return abortOnFirstSuccess;
  }

  public OptionSimpleVarchar getOptionTheContainedString()
  {
    return optionTheContainedString;
  }
}
