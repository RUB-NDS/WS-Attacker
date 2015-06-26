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
package wsattacker.library.intelligentdos;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;

import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.Metric;
import wsattacker.library.intelligentdos.success.SuccessDecider;

/**
 * In this state it will be decided if the library has to switch to the safety mode. This means that für each tampered
 * attack a own untampered attack will be generated.
 * 
 * @author Christian Altmeier
 */
public class SuspiciousState
    implements DoSState
{

    private final Logger logger = Logger.getLogger( getClass() );

    private static final double UTR_RATIO_LOWER = getFromProperty( "utr.ratio.lower", 0.5 );

    private static final double UTR_RATIO_UPPER = getFromProperty( "utr.ratio.upper", 2 );

    private AttackModel untampered = null;

    @Override
    public String getName()
    {
        return "suspicious state";
    }

    @Override
    public void update( IntelligentDoSLibraryImpl STATE_CONTEXT, AttackModel attackModel )
    {
        if ( untampered == null )
        {
            // set the attack model for later compare
            untampered = attackModel;

            // create a new untampered attack for verification
            STATE_CONTEXT.setCurrentAttack( STATE_CONTEXT.createVerifyUntampered( true ) );
            STATE_CONTEXT.setHasFurtherAttack( true );
        }
        else
        {
            SuccessDecider successDecider = STATE_CONTEXT.getSuccessDecider();

            double ratio =
                successDecider.calculateRatio( STATE_CONTEXT.getCurrentUntampered(), attackModel.getDurationArray() );
            double ratioFormatted = Math.round( ratio * 100.0 ) / 100.0;

            if ( isSuspicious( ratio ) )
            {

                logger.info( String.format( "The ratio (%s) of the untampered requests stay suspicious. "
                    + "Switch to safety mode.", ratioFormatted ) );

                STATE_CONTEXT.setCurrentAttack( STATE_CONTEXT.createVerifyUntampered( false ) );
                STATE_CONTEXT.setHasFurtherAttack( true );
                STATE_CONTEXT.setDoSState( new SafetyState() );
            }
            else
            {
                logger.info( String.format( "The suspicious behavior could not be confirmed. The ratio was %s.",
                                            ratioFormatted ) );

                // switch to untampered state and update utr
                STATE_CONTEXT.setCurrentAttack( STATE_CONTEXT.createNewUntampered( false ) );
                STATE_CONTEXT.setHasFurtherAttack( true );
                STATE_CONTEXT.setDoSState( new UntamperedState() );
            }
        }
    }

    @Override
    public void updateTestProbes( Metric metric )
    {
        // we are not interested in testprobes in this state
    }

    public static boolean isSuspicious( double ratio )
    {
        return ratio < UTR_RATIO_LOWER || ratio > UTR_RATIO_UPPER;
    }

    private static double getFromProperty( String string, double defaultValue )
    {
        try
        {
            String property = System.getProperty( string );
            if ( StringUtils.isEmpty( property ) )
            {
                return defaultValue;
            }
            else
            {
                return Double.parseDouble( property );
            }
        }
        catch ( NumberFormatException e )
        {
            return defaultValue;
        }
    }

}
