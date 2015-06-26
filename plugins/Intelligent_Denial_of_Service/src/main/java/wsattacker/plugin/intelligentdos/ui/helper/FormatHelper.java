/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Altmeier
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
package wsattacker.plugin.intelligentdos.ui.helper;

import java.util.List;

import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.DoSParam;
import wsattacker.library.intelligentdos.common.RequestType;
import wsattacker.library.intelligentdos.common.SuccessfulAttack;
import wsattacker.library.intelligentdos.helper.CommonParamItem;

/**
 * @author Christian Altmeier
 */
public class FormatHelper
{

    public static String toHTML( AttackModel attackModel )
    {
        StringBuilder builder = new StringBuilder();
        builder.append( "<html><body><table>" );
        builder.append( "<tr><td>Attack Name:</td><td>" ).append( attackModel.getDoSAttack().getName() ).append( "</td></tr>" );
        builder.append( "<tr><td>Request Type:</td><td>" ).append( attackModel.getRequestType() ).append( "</td></tr>" );

        if ( attackModel.getRequestType() == RequestType.TAMPERED )
        {
            List<DoSParam<?>> currentParams = attackModel.getDoSAttack().getCurrentParams();

            builder.append( "<tr><td valign=\"top\" rowspan=\"" ).append( currentParams.size() ).append( "\">Parameter:</td>" );

            int index = 0;
            for ( DoSParam<?> doSParam : currentParams )
            {
                if ( index != 0 )
                {
                    builder.append( "</tr><tr>" );
                }

                builder.append( "<td>" ).append( doSParam.getDescription() ).append( "</td><td>" ).append( doSParam.getValueAsString() ).append( "</td>" );

                index++;
            }
            builder.append( "</tr>" );

            String positionString = attackModel.getPosition().toString();
            builder.append( "<tr><td>Position:</td><td>" ).append( positionString ).append( "</td></tr>" );
            builder.append( "<tr><td>Payload Position:</td><td>" ).append( attackModel.getPayloadPosition() ).append( "</td></tr>" );
        }
        builder.append( "<tr><td>Number of Threads:</td><td>" ).append( attackModel.getNumberOfThreads() ).append( "</td></tr>" );
        builder.append( "<tr><td>Number of Requests:</td><td>" ).append( attackModel.getNumberOfRequests() ).append( "</td></tr>" );
        builder.append( "<tr><td>Millis between Requests:</td><td>" ).append( attackModel.getMilliesBetweenRequests() ).append( "</td></tr>" );
        builder.append( "</table></body></html>" );

        return builder.toString();
    }

    public static String toHTML( SuccessfulAttack sa )
    {
        CommonParamItem paramItem = sa.getParamItem();

        StringBuilder builder = new StringBuilder();
        builder.append( "<html><body><table>" );
        builder.append( "<tr><td>Attack Name:</td><td>" ).append( sa.getDoSAttack().getName() ).append( "</td></tr>" );

        List<DoSParam<?>> currentParams = sa.getDoSAttack().getCurrentParams();

        builder.append( "<tr><td valign=\"top\" rowspan=\"" ).append( currentParams.size() ).append( "\">Parameter:</td>" );

        int index = 0;
        for ( DoSParam<?> doSParam : currentParams )
        {
            if ( index != 0 )
            {
                builder.append( "</tr><tr>" );
            }

            builder.append( "<td>" ).append( doSParam.getDescription() ).append( "</td><td>" ).append( doSParam.getValueAsString() ).append( "</td>" );

            index++;
        }
        builder.append( "</tr>" );

        String positionString = sa.getPosition().toString();
        builder.append( "<tr><td>Position:</td><td>" ).append( positionString ).append( "</td></tr>" );
        builder.append( "<tr><td>Payload Position:</td><td>" ).append( sa.getPayloadPosition() ).append( "</td></tr>" );
        builder.append( "<tr><td>Number of Threads:</td><td>" ).append( paramItem.getNumberOfThreads() ).append( "</td></tr>" );
        builder.append( "<tr><td>Number of Requests:</td><td>" ).append( paramItem.getNumberOfRequests() ).append( "</td></tr>" );
        builder.append( "<tr><td>Millis between Requests:</td><td>" ).append( paramItem.getMilliesBetweenRequests() ).append( "</td></tr>" );
        builder.append( "</table></body></html>" );

        return builder.toString();
    }

}
