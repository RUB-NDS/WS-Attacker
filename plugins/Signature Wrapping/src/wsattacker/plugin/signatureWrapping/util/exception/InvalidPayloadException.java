package wsattacker.plugin.signatureWrapping.util.exception;

public class InvalidPayloadException extends Exception
{
  private static final long serialVersionUID = 1L;

  public InvalidPayloadException(Exception e) {
    super(e);
  }
  
  public InvalidPayloadException(String message) {
    super(message);
  }
}
