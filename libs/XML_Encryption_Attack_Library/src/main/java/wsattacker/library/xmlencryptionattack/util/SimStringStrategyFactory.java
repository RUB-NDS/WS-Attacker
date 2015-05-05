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

package wsattacker.library.xmlencryptionattack.util;

import uk.ac.shef.wit.simmetrics.similaritymetrics.DiceSimilarity;
import uk.ac.shef.wit.simmetrics.similaritymetrics.InterfaceStringMetric;
import uk.ac.shef.wit.simmetrics.similaritymetrics.JaccardSimilarity;
import uk.ac.shef.wit.simmetrics.similaritymetrics.Jaro;
import uk.ac.shef.wit.simmetrics.similaritymetrics.JaroWinkler;
import uk.ac.shef.wit.simmetrics.similaritymetrics.Levenshtein;
import uk.ac.shef.wit.simmetrics.similaritymetrics.MongeElkan;
import uk.ac.shef.wit.simmetrics.similaritymetrics.QGramsDistance;

/**
 * @author Dennis
 */
public class SimStringStrategyFactory
{
    public enum SimStringStrategy
    {
        DICE_COEFF, JARO, JAROWINKLER, LEVENSTHEIN, JACCARD, MONGEELKAN, QGRAMS
    };

    private SimStringStrategyFactory()
    {

    }

    public static InterfaceStringMetric createSimStringStrategy( final SimStringStrategy strategyType )
    {
        switch ( strategyType )
        {
            case DICE_COEFF:
                return new DiceSimilarity();
            case JARO:
                return new Jaro();
            case JAROWINKLER:
                return new JaroWinkler();
            case LEVENSTHEIN:
                return new Levenshtein();
            case JACCARD:
                return new JaccardSimilarity();
            case MONGEELKAN:
                return new MongeElkan();
            case QGRAMS:
                return new QGramsDistance();
            default:
                throw new IllegalArgumentException( "No valid SimStringStrategyType!" );
        }
    }
}
