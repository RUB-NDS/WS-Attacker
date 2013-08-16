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

import java.io.*;
import java.util.logging.*;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 *
 * @author christian
 */
public final class SchemaAnalyzerFactory {

    public static final String SCHEMA_DIRECTORY = "/XML Schema/";
    public static final String NULL = "NULL";
    public static final String EMPTY = "EMPTY";
    public static final String ALL = "ALL";
    public static final String MINIMAL = "MINIMAL";
    public static final String SAML = "SAML";
    public static final String SAML11 = "SAML11";
    public static final String SAML20 = "SAML20";
    public static final String WEBSERVICE = "Web Service";
    private final static String[] SCHEMAFILES_MINIMAL = {
        "xmldsig-core-schema.xsd",
        "xmldsig11-schema.xsd",
        "xmldsig-filter2.xsd"
    };
    private final static String[] SCHEMAFILES_WEBVSERVICE = {
        "soap11.xsd", "soap12.xsd",
        "wsa.xsd",
        "wssec-1.0.xsd", "wssec-1.1.xsd",
        "wsu.xsd",};
    private final static String[] SCHEMAFILES_SAML11 = {
        "saml11.xsd",
        "saml11p.xsd"
    };
    private final static String[] SCHEMAFILES_SAML20 = {
        "saml20.xsd",
        "saml20p.xsd",
        "saml-metadata-ext-query.xsd",
        "saml-metadata-ui-v1.0.xsd",
        "saml-schema-authn-context-types-2.0.xsd",
        "saml-schema-metadata-2.0.xsd"
    };

    /**
     * Creates a SchemaAnalyzerImpl with NO Schemas contained.
     * This is NOT THE SAME as creating a NullSchemaAnalyzer.
     * However, this is equal to getInstance(EMPTY)
     *
     * @return
     */
    public static SchemaAnalyzer getInstance() {
        return new SchemaAnalyzerImpl();
    }

    /**
     * Creates a SchemaAnalyzerImpl with predefined Schemas.
     * Use the SchemaAnalayzerFactory static String constants as arguments.
     * If the IDENTIFIER is unknown, there will be a fall-back to MINIMAL
     * Schema files.
     *
     * @param IDENTIFIER: see SchemaAnalayzerFactory static String constants.
     *
     * @return
     */
    public static SchemaAnalyzer getInstance(String IDENTIFIER) {
        SchemaAnalyzer schemaAnalyzer = null;
        if (IDENTIFIER == null || IDENTIFIER.equals(NULL)) {
            schemaAnalyzer = new NullSchemaAnalyzer();
        } else {
            schemaAnalyzer = getInstance();
            if (!IDENTIFIER.equals(EMPTY)) {
                addSchemasToAnalyzer(schemaAnalyzer, SCHEMAFILES_MINIMAL);
            }
            if (IDENTIFIER.equals(WEBSERVICE) || IDENTIFIER.equals(ALL)) {
                addSchemasToAnalyzer(schemaAnalyzer, SCHEMAFILES_WEBVSERVICE);
            }
            if (IDENTIFIER.equals(SAML11) || IDENTIFIER.equals(SAML) || IDENTIFIER.equals(ALL)) {
                addSchemasToAnalyzer(schemaAnalyzer, SCHEMAFILES_SAML11);
            }
            if (IDENTIFIER.equals(SAML20) || IDENTIFIER.equals(SAML) || IDENTIFIER.equals(ALL)) {
                addSchemasToAnalyzer(schemaAnalyzer, SCHEMAFILES_SAML20);
            }
        }
        return schemaAnalyzer;
    }

    public static Document getSchemaDocument(String identifier) throws SAXException, IOException {
        String filename = SCHEMA_DIRECTORY + identifier;
        try {
            return DomUtilities.readDocument(SchemaAnalyzerFactory.class.getResourceAsStream(filename));
        } catch (SAXException ex) {
            Logger.getLogger(SchemaAnalyzerFactory.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (IOException ex) {
            Logger.getLogger(SchemaAnalyzerFactory.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        }
    }

    private static void addSchemasToAnalyzer(SchemaAnalyzer schemaAnalyzer, String[] schemaFiles) {
        for (String cur : schemaFiles) {
            Document xsd;
            try {
                xsd = getSchemaDocument(cur);
//				System.out.println("Adding: " + filename);
            } catch (SAXException ex) {
                continue;
            } catch (IOException ex) {
                continue;
            }
            schemaAnalyzer.appendSchema(xsd);
        }
    }

    private SchemaAnalyzerFactory() {
    }
}
