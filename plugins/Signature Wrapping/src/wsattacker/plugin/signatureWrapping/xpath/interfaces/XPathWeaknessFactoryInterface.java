package wsattacker.plugin.signatureWrapping.xpath.interfaces;

import java.util.List;

import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzerInterface;
import wsattacker.plugin.signatureWrapping.xpath.parts.AbsoluteLocationPath;

/**
 * Interface for creating a List of XPathWeaknesses.
 * Factory Pattern.
 */
public interface XPathWeaknessFactoryInterface
{
  public List<XPathWeakness> generate(AbsoluteLocationPath xpath,
                                      Element signedElement,
                                      Element payloadElement,
                                      SchemaAnalyzerInterface schemaAnalyser);
}
