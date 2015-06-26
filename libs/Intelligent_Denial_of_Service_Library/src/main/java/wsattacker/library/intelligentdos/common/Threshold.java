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
package wsattacker.library.intelligentdos.common;

import java.util.List;

import wsattacker.library.intelligentdos.dos.DoSAttack;

/**
 * @author Christian Altmeier
 */
public class Threshold
{

    private final DoSAttack minimum;

    private final DoSAttack maximum;

    public Threshold( DoSAttack minimum, DoSAttack maximum )
    {
        this.minimum = minimum;
        this.maximum = maximum;
    }

    public DoSAttack getMinimum()
    {
        return minimum;
    }

    public DoSAttack getMaximum()
    {
        return maximum;
    }

    @Override
    public String toString()
    {
        StringBuilder builder = new StringBuilder();
        builder.append( "Threshold[" );
        builder.append( "dosAttack=" ).append( minimum.getName() );

        List<DoSParam<?>> minParams = minimum.getCurrentParams();
        List<DoSParam<?>> maxParams = maximum.getCurrentParams();
        for ( int index = 0; index < minParams.size(); index++ )
        {
            DoSParam<?> minParam = minParams.get( index );
            DoSParam<?> maxParam = maxParams.get( index );

            if ( !minParam.getValueAsString().equals( maxParam.getValueAsString() ) )
            {
                builder.append( ", " ).append( minParam.getDescription() ).append( "=" ).append( minParam.getValueAsString() ).append( "-" ).append( maxParam.getValueAsString() );
            }
        }

        builder.append( "]" );
        return builder.toString();
    }

}
