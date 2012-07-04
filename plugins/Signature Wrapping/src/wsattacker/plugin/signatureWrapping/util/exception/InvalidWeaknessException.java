package wsattacker.plugin.signatureWrapping.util.exception;

public class InvalidWeaknessException extends Exception
{
  private static final long serialVersionUID = 1L;

  public InvalidWeaknessException(Exception e)
  {
    super(e);
  }

  public InvalidWeaknessException(String msg)
  {
    super(msg);
  }

  public InvalidWeaknessException()
  {
    super();
  }
}
