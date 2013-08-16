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
package wsattacker.library.signatureWrapping.xpath.interfaces;

import java.util.*;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.signatureWrapping.option.PayloadElement;
import wsattacker.library.signatureWrapping.option.SignedElement;
import wsattacker.library.signatureWrapping.xpath.parts.AbsoluteLocationPath;

/**
 * Interface for creating a List of XPathWeaknesses.
 * Factory Pattern.
 */
public interface XPathWeaknessFactoryInterface {

    public List<XPathWeaknessInterface> generate(AbsoluteLocationPath xpath,
      SignedElement signedElement,
      PayloadElement payloadElement,
      SchemaAnalyzer schemaAnalyser);
}
