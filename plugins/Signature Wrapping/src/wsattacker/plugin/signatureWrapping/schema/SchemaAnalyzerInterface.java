package wsattacker.plugin.signatureWrapping.schema;

import java.util.List;

import javax.xml.namespace.QName;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * An interface for the SchemaAnalyzer.
 * There are two implemetations for it:
 * 1) A Real Schema Analyzer
 * 2) A Null Schema Analyzer, which allows any element to have any child element.
 */
public interface SchemaAnalyzerInterface
{

  public abstract void setFilterList(List<QName> filterList);

  public abstract void appendSchema(Document newSchema);

  /**
   * Find an expansion point in the Schema starting with Node fromHere. The returned Elements are not part of the old
   * Document. Instead, a new Document is used where each possible but not occuring element is added. So, the original
   * Document will not be modified! Elements in the filterList will not be searched.
   * 
   * @param fromHere
   * @param filterList
   */
  public abstract List<AnyElementPropertiesInterface> findExpansionPoint(Element fromHere);

}
