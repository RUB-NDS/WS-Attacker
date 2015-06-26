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

import java.util.List;

import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.Metric;
import wsattacker.library.intelligentdos.common.SuccessfulAttack;
import wsattacker.library.intelligentdos.common.Threshold;
import wsattacker.library.intelligentdos.dos.DoSAttack;

/**
 * @author Christian Altmeier
 */
public interface IntelligentDoSLibrary
{

    void setAttacks( DoSAttack[] attacks );

    void initialize();

    boolean hasFurtherAttack();

    AttackModel nextAttack();

    boolean wasSuccessful();

    void update( AttackModel attackModel );

    void updateTestProbes( Metric metric );

    /**
     * The content for the testprobes
     * 
     * @return
     */
    String getTestProbeContent();

    List<SuccessfulAttack> getSuccessfulAttacks();

    List<DoSAttack> getNotPossible();

    List<Threshold> getThresholds();

    double getMaximumRequestsPerSecond();

}
