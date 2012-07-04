package wsattacker.plugin.optionsTester.option;

import java.util.ArrayList;
import java.util.List;

import wsattacker.main.composition.plugin.option.AbstractOptionChoice;
import wsattacker.main.composition.testsuite.CurrentOperationObserver;
import wsattacker.main.testsuite.TestSuite;

import com.eviware.soapui.impl.wsdl.WsdlOperation;
import com.eviware.soapui.model.iface.Operation;

/**
 * Mainly copied from the SoapActionSpoofing plugin.
 */
public class OptionSoapAction extends AbstractOptionChoice implements CurrentOperationObserver
{
  private static final long serialVersionUID = 1L;
  List<String>              choices;
  String                    selected;
  final String              MANUAL           = "No";

  public OptionSoapAction(String name,
                          String description)
  {
    super(name, description);
    choices = new ArrayList<String>();
    clearChoices();
    setChoice(0);
    TestSuite.getInstance().getCurrentOperation().addCurrentOperationObserver(this);
  }

  private void clearChoices()
  {
    choices.clear();
    choices.add(MANUAL);
  }

  @Override
  public List<String> getChoices()
  {
    return choices;
  }

  @Override
  public boolean setChoice(String value)
  {
    if (isValid(value))
    {
      selected = value;
      notifyValueChanged();
      return true;
    }
    return false;
  }

  @Override
  public boolean setChoice(int index)
  {
    if (isValid(index))
    {
      selected = choices.get(index);
      notifyValueChanged();
      return true;
    }
    return false;
  }

  @Override
  public int getChoice()
  {
    return choices.indexOf(selected);
  }

  @Override
  public boolean isValid(String value)
  {
    return (value == null) || choices.contains(value);
  }

  @Override
  public boolean isValid(int choice)
  {
    return (choice >= -1) && (choice < choices.size());
  }

  @Override
  public boolean parseValue(String value)
  {
    return setChoice(value);
  }

  @Override
  public String getValueAsString()
  {
    return selected;
  }

  @Override
  public void currentOperationChanged(WsdlOperation newOperation,
                                      WsdlOperation oldOperation)
  {
    clearChoices();
    for (Operation operation : newOperation.getInterface().getOperationList())
    {
      choices.add(operation.getName());
    }
    if (newOperation.getName().equals(getValueAsString()))
    {
      setChoice(0);
    }
    choices.remove(newOperation.getName());
    notifyValueChanged();
  }

  @Override
  public void noCurrentOperation()
  {
    choices.clear();
    setChoice(0);
  }

}
