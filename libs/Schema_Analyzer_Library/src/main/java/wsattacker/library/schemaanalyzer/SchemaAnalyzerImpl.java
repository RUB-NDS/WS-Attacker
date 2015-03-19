/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Mainka
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
package wsattacker.library.schemaanalyzer;

import java.util.*;
import javax.xml.namespace.QName;
import javax.xml.xpath.XPathExpressionException;
import org.apache.log4j.Logger;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import static wsattacker.library.schemaanalyzer.XmlSchemaConstants.NAME_SCHEMA_ELEMENT;
import static wsattacker.library.schemaanalyzer.XmlSchemaConstants.NAME_ELEMENTLOCALNAME;
import static wsattacker.library.schemaanalyzer.XmlSchemaConstants.NAME_ANY_ELEMENT;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import static wsattacker.library.xmlutilities.namespace.NamespaceConstants.URI_NS_SCHEMA;

public class SchemaAnalyzerImpl
    implements SchemaAnalyzer
{

    private final static Logger LOG = Logger.getLogger( SchemaAnalyzerImpl.class );

    Document analyzingDocument, expandedAnalyzingDocument;

    Map<String, Document> schemaMap;

    List<QName> filterList;

    public SchemaAnalyzerImpl()
    {
        schemaMap = new HashMap<String, Document>();
        analyzingDocument = null;
        expandedAnalyzingDocument = null;
        filterList = new ArrayList<QName>();
    }

    public Document getExpandedAnalyzingDocument()
    {
        return expandedAnalyzingDocument;
    }

    public Document getAnalyzingDocument()
    {
        return analyzingDocument;
    }

    public List<QName> getFilterList()
    {
        return filterList;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.plugin.signatureWrapping.schema.SchemaAnalyserInterface# setFilterList(java.util.List)
     */
    @Override
    public void setFilterList( List<QName> filterList )
    {
        this.filterList = filterList;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.plugin.signatureWrapping.schema.SchemaAnalyserInterface# appendSchema(org.w3c.dom.Document)
     */
    @Override
    public void appendSchema( Document newSchema )
    {
        Element newSchemaRoot = newSchema.getDocumentElement();
        // Only Append if Document is a Schema Document
        if ( newSchema != null && URI_NS_SCHEMA.equals( newSchemaRoot.getNamespaceURI() )
            && "schema".equals( newSchemaRoot.getLocalName() ) )
        {
            String targetNamespace = newSchema.getDocumentElement().getAttribute( "targetNamespace" );
            schemaMap.put( targetNamespace, newSchema );
        }
    }

    public void clearSchemas()
    {
        schemaMap.clear();
    }

    public boolean isInCurrentAnalysis( Node n )
    {
        boolean result =
            ( analyzingDocument != null && ( n.getOwnerDocument().getDocumentElement().isEqualNode( analyzingDocument.getDocumentElement() ) ) );
        LOG.trace( String.format( "isInCurrent: %b", result ) );
        return result;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.plugin.signatureWrapping.schema.SchemaAnalyserInterface# findExpansionPoint(org.w3c.dom.Element)
     */
    @Override
    public Set<AnyElementProperties> findExpansionPoint( Element fromHere )
    {
        if ( !isInCurrentAnalysis( fromHere ) )
        {
            LOG.trace( "New Document to analyze!" );
            // We will clone the Document of Node fromHere and add all possible
            // expansionpoints
            expandedAnalyzingDocument =
                DomUtilities.createNewDomFromNode( fromHere.getOwnerDocument().getDocumentElement() );
            analyzingDocument = fromHere.getOwnerDocument();
        }
        Document expandedDoc = expandedAnalyzingDocument; // get current
                                                          // analyzed document
        Element start = DomUtilities.findCorrespondingElement( expandedDoc, fromHere ); // corresponding "fromHere"
        // return a Map of <Node,Properties>
        Set<AnyElementProperties> result = new TreeSet<AnyElementProperties>();
        findExpansionPoint( result, start );
        return result;
    }

    private void findExpansionPoint( Set<AnyElementProperties> result, Element start )
    {
        LOG.trace( "Find expansion point of Element '" + start.getNodeName() + "'" );
        // Shall the Element be filtered?
        if ( filterList.contains( new QName( start.getNamespaceURI(), start.getLocalName() ) ) )
        {
            LOG.trace( "\tFound in filterList -> Abort" );
            return;
        }
        // Find allowed child elements of start element
        List<Element> possibleChildElementList = findPossibleChildElements( start );
        boolean hasAny = false;
        for ( Element possibleChild : possibleChildElementList )
        {

            if ( "any".equals( possibleChild.getLocalName() ) )
            {
                if ( !hasAny )
                {
                    hasAny = true; // add only one any child element
                    result.add( new AnyElementPropertiesImpl( possibleChild, start ) );
                    LOG.trace( "\t-> xs:any <- allowed!" );
                }
            }
            else
            {
                String localName = possibleChild.getAttribute( "name" );
                String[] prefixNamespacePair = getTargetNamespace( possibleChild );
                LOG.trace( "\tAllowed Child: '" + prefixNamespacePair[1] + ":" + localName + "'" );
                // Check if Element exists
                if ( DomUtilities.findChildren( start, localName, prefixNamespacePair[1], false ).isEmpty() )
                {

                    // Check if an identical ancestor element exists:
                    if ( elementHasSpecificAncestor( start, localName, prefixNamespacePair[1] ) )
                    {
                        LOG.trace( "\t\tAncestor with same name already exists -> *NOT* Created" );
                    }
                    else
                    {
                        createChildElementForElement( start, localName, prefixNamespacePair[1], prefixNamespacePair[0] );
                        LOG.trace( "\t\tDoes not exist -> Created" );
                    }
                }
            }
        }
        // Recursive with all child elements
        NodeList theChildren = start.getChildNodes();
        for ( int i = 0; i < theChildren.getLength(); ++i )
        {
            if ( theChildren.item( i ).getNodeType() == Node.ELEMENT_NODE )
            {
                findExpansionPoint( result, (Element) theChildren.item( i ) );
            }
        }
    }

    /**
     * Checks theElement has an ancestor element with given ancestorLocalName and ancestorNamespaceURI.
     * 
     * @param theElement
     * @param ancestorLocalName
     * @param ancestorNamespaceURI
     * @return
     */
    public boolean elementHasSpecificAncestor( Element theElement, String ancestorLocalName, String ancestorNamespaceURI )
    {
        boolean ret = false;
        Node up = theElement.getParentNode();

        while ( up != null && up.getNodeType() == Node.ELEMENT_NODE )
        {
            if ( up.getNamespaceURI().equals( ancestorNamespaceURI ) && up.getLocalName().equals( ancestorLocalName ) )
            {
                ret = true;
                break;
            }
            up = up.getParentNode();
        }
        return ret;
    }

    public void createChildElementForElement( Element theElement, String localName, String namespaceURI,
                                              String fallbackPrefix )
    {
        // search if there is already a prefix binded to the namespaceURI
        String prefix = DomUtilities.getPrefix( theElement, namespaceURI );
        if ( prefix == null )
        {
            // prefix not in elements scope.
            // use prefix from schema
            prefix = fallbackPrefix;
            if ( prefix == null )
            {
                // if there is now prefix defined in the schema
                // use no prefix.
                prefix = "";
            }
        }
        else if ( !prefix.isEmpty() )
        {
            // if we have a prefix, the QName must be
            // written as prefix:localName
            prefix = prefix + ':';
        }
        LOG.info( String.format( "\t-> Creating element %s:%s%s", namespaceURI, prefix, localName ) );
        theElement.appendChild( theElement.getOwnerDocument().createElementNS( theElement.getNamespaceURI(),
                                                                               prefix + localName ) );
    }

    public List<Element> findPossibleChildElements( Element element )
    {
        return findPossibleChildElements( element.getNamespaceURI(), element.getLocalName() );
    }

    public List<Element> findPossibleChildElements( String namespaceURI, String localName )
    {
        Element elementSchema = findElementInSchema( namespaceURI, localName );
        if ( elementSchema == null )
        {
            LOG.info( String.format( "Could not find any child elements for element '%s:%s'", namespaceURI, localName ) );
            return new ArrayList<Element>();
        }
        Element complexType = findComplexTypeForElement( elementSchema );
        if ( complexType == null )
        {
            LOG.info( String.format( "Element '%s:%s' seems to not to have a complex declaration.", namespaceURI,
                                     localName ) );
            return new ArrayList<Element>();
        }
        List<Element> refferingElementList = DomUtilities.findChildren( complexType, "element", URI_NS_SCHEMA, true );
        List<Element> possibleChildElementList = DomUtilities.findChildren( complexType, "any", URI_NS_SCHEMA, true );
        for ( Element referringElement : refferingElementList )
        {
            Element schemaElement = dereferenceElement( referringElement );
            if ( schemaElement != null )
            {
                possibleChildElementList.add( schemaElement );
            }
        }
        return possibleChildElementList;
    }

    public Element findComplexTypeInSchema( String namespaceURI, String elementTypeLocalName )
    {
        return findXInSchema( "complexType", namespaceURI, elementTypeLocalName );
    }

    public Element findElementInSchema( String namespaceURI, String localName )
    {
        return findXInSchema( "element", namespaceURI, localName );
    }

    private Element findXInSchema( String x, String namespaceURI, String localName )
    {
        Document theSchema = schemaMap.get( namespaceURI );
        if ( theSchema == null )
        {
            return null;
        }
        String xpath;
        xpath =
            "//*[local-name()='" + x + "' and namespace-uri()='" + URI_NS_SCHEMA + "' and @name='" + localName + "']";
        List<Element> complexTypeList;
        try
        {
            complexTypeList = (List<Element>) DomUtilities.evaluateXPath( theSchema, xpath );
        }
        catch ( XPathExpressionException e )
        {
            throw new IllegalArgumentException( "Invalid XPath. This should never happen.", e );
        }
        if ( complexTypeList.size() == 0 )
        {
            // Nothing found, abort
            return null;
        }
        else if ( complexTypeList.size() > 1 )
        {
            LOG.warn( String.format( "More than one possible schema definition found for %s:%s", namespaceURI,
                                     localName ) );
        }
        return complexTypeList.get( 0 );
    }

    public Element dereferenceElement( Element referringElement )
    {
        Element elementSchema = null;
        String ref = referringElement.getAttribute( "ref" );
        int colonPosition = ref.indexOf( ':' );
        if ( colonPosition > 0 )
        {
            // extract element's localname
            String elementTypeLocalName = ref.substring( colonPosition + 1 );
            // extract element's prefix
            String elementPrefix = ref.substring( 0, colonPosition );
            // find element's namespaceURI
            String elementNamespaceURI = DomUtilities.getNamespaceURI( referringElement, elementPrefix );
            // find the complexType element definition
            elementSchema = findElementInSchema( elementNamespaceURI, elementTypeLocalName );
        }
        return elementSchema;
    }

    public Element findComplexTypeForElement( Element elementSchema )
    {
        Element compexTypeSchema = null;
        String type = elementSchema.getAttribute( "type" );
        if ( type.isEmpty() )
        {
            // no type reference found
            // maybe subelement is complexType?
            List<Element> complexChildElementList =
                DomUtilities.findChildren( elementSchema, "complexType", URI_NS_SCHEMA, true );
            if ( !complexChildElementList.isEmpty() )
            {
                compexTypeSchema = complexChildElementList.get( 0 );
            }
        }
        else
        {
            int colonPosition = type.indexOf( ':' );
            if ( colonPosition > 0 )
            {
                // extract element's localname
                String elementTypeLocalName = type.substring( colonPosition + 1 );
                // extract element's prefix
                String elementPrefix = type.substring( 0, colonPosition );
                // find element's namespaceURI
                String elementNamespaceURI = DomUtilities.getNamespaceURI( elementSchema, elementPrefix );
                // find the complexType element definition
                compexTypeSchema = findComplexTypeInSchema( elementNamespaceURI, elementTypeLocalName );
            }
        }
        return compexTypeSchema;
    }

    /**
     * Returns a StringPair of the targetNamespace of an Schema-Element.
     * 
     * @param x Schema Element
     * @return String[2] with {prefix,targetNS}
     */
    public String[] getTargetNamespace( Element x )
    {
        Node parent = x;
        do
        {
            parent = parent.getParentNode();
            if ( parent != null && "schema".equals( parent.getLocalName() )
                && URI_NS_SCHEMA.equals( parent.getNamespaceURI() ) )
            {
                break;
            }
        }
        while ( parent != null );
        Element p;
        if ( parent instanceof Element )
        {
            p = (Element) parent;
        }
        else
        {
            return new String[] { "", "" };
        }
        String targetNS = p.getAttribute( "targetNamespace" );
        String prefix = "";
        if ( targetNS.isEmpty() )
        {
            return new String[] { prefix, targetNS };
        }
        NamedNodeMap attributes = parent.getAttributes();
        for ( int i = 0; i < attributes.getLength(); ++i )
        {
            Node attribute = attributes.item( i );
            if ( attribute.getPrefix() != null && attribute.getPrefix().equals( "xmlns" )
                && attribute.getTextContent().equals( targetNS ) )
            {
                prefix = attribute.getLocalName();
                break;
            }
        }
        return new String[] { prefix, targetNS };
    }
}
