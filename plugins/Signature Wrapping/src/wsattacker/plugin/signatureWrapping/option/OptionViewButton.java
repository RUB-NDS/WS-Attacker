package wsattacker.plugin.signatureWrapping.option;

import wsattacker.gui.composition.AbstractOptionGUI;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOptionComplex;

/**
 * Simple option which just offers a button to view all possible XSW messages.
 */
public class OptionViewButton extends AbstractOptionComplex
{
  
  public OptionViewButton() {
    this("View", "Display the wrapping messages.");
  }

  protected OptionViewButton(String name,
                             String description)
  {
    super(name, description);
  }

  private static final long serialVersionUID = 1L;

  @Override
  public AbstractOptionGUI getComplexGUI(ControllerInterface controller,
                                         AbstractPlugin plugin)
  {
    return new OptionViewButtonGUI(controller, plugin, this);
  }

  @Override
  /**
   * Nothing to do
   */
  public boolean isValid(String value)
  {
    return true;
  }

  @Override
  /**
   * Nothing to do
   */
  public boolean parseValue(String value)
  {
    return true;
  }

  @Override
  /**
   * Nothing to do
   */
  public String getValueAsString()
  {
    return getName();
  }

}
