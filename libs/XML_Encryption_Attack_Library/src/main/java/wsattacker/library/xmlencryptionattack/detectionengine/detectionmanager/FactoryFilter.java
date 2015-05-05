/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Dennis Kupser
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

package wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager;

import wsattacker.library.xmlencryptionattack.detectionengine.filter.base.AbstractDetectionFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.concrete.AvoidedDocErrorFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.concrete.TimestampFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.concrete.XMLEncryptionFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.concrete.XMLSignatureFilter;

public class FactoryFilter
{

    private FactoryFilter()
    {

    }

    public static AbstractDetectionFilter createFilter( final DetectFilterEnum filterType )
    {
        // decision map better?
        switch ( filterType )
        {
            case SIGNATUREFILTER:
                return new XMLSignatureFilter( filterType );
            case ENCRYPTIONFILTER:
                return new XMLEncryptionFilter( filterType );
            case AVOIDDOCFILTER:
                return new AvoidedDocErrorFilter( filterType );
            case TIMESTAMPFILTER:
                return new TimestampFilter( filterType );
            default:
                throw new IllegalArgumentException( "No valid FilterType!" );
        }
    }

}