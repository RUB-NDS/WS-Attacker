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
package wsattacker.library.intelligentdos.helper;

import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * @author Christian Altmeier
 */
public class IterateModel
    implements Iterator<Integer>, Cloneable
{

    private static final int UNSET = -1;

    public enum IterateStrategie
    {
        ADD
        {
            @Override
            int inc( int a, int b )
            {
                return a + b;
            }
        },
        SUB
        {
            @Override
            int inc( int a, int b )
            {
                return a - b;
            }

            @Override
            boolean end( int a, int b )
            {
                return a < b;
            }
        },
        MUL
        {
            @Override
            int inc( int a, int b )
            {
                return a * b;
            }
        };

        abstract int inc( int a, int b );

        boolean end( int a, int b )
        {
            return a >= b;
        }
    }

    public enum IncreaseIncrementStrategie
    {
        NO
        {
            @Override
            double inc( int a )
            {
                return 1;
            }
        },
        MODERATE
        {
            @Override
            double inc( int a )
            {
                return 1 + ( a * 0.25 );
            }
        },
        AGGRESSIV
        {
            @Override
            double inc( int a )
            {
                return 1.5 + ( a * 0.5 );
            }
        };

        abstract double inc( int a );
    }

    private boolean stop;

    private int startAt = 0;

    private int stopAt = Integer.MAX_VALUE;

    private int initialIncrement = 1;

    private int currentValue = UNSET;

    private int increaseCount = 0;

    private int increment = 1;

    private IterateStrategie strategie = IterateStrategie.ADD;

    private IncreaseIncrementStrategie increaseStrategie = IncreaseIncrementStrategie.NO;

    public static IterateModelBuilder custom()
    {
        return IterateModelBuilder.create();
    }

    public int getStartAt()
    {
        return startAt;
    }

    public void startAt( int startAt )
    {
        this.startAt = startAt;
    }

    public int getStopAt()
    {
        return stopAt;
    }

    public void stopAt( int stopAt )
    {
        this.stopAt = stopAt;
    }

    public int getIncrement()
    {
        return increment;
    }

    public void setIncrement( int increment )
    {
        this.initialIncrement = increment;
        this.increment = increment;
    }

    public IterateStrategie getIterateStrategie()
    {
        return strategie;
    }

    public void setIterateStrategie( IterateStrategie iterateStrategie )
    {
        this.strategie = iterateStrategie;
    }

    public void setIncreaseIncrementStrategie( IncreaseIncrementStrategie increaseIncrementStrategie )
    {
        this.increaseStrategie = increaseIncrementStrategie;
    }

    public void increaseIncrement()
    {
        increaseCount++;
        double inc = increaseStrategie.inc( increaseCount );
        increment = (int) ( increment * inc );
    }

    public int increment( int numberAttributes )
        throws NoSuchElementException
    {
        if ( stop )
        {
            throw new NoSuchElementException();
        }

        int inc = strategie.inc( numberAttributes, increment );
        if ( !stop && strategie.end( inc, stopAt ) )
        {
            stop = true;
            return stopAt;
        }
        else
        {
            return inc;
        }
    }

    @Override
    public Integer next()
        throws NoSuchElementException
    {
        if ( currentValue == UNSET )
        {
            currentValue = startAt;
            increment = initialIncrement;
        }
        else
        {
            try
            {
                currentValue = increment( currentValue );
            }
            catch ( NoSuchElementException e )
            {
                throw new java.util.NoSuchElementException( "no more elements to iterate over" );
            }
        }
        return currentValue;
    }

    @Override
    public boolean hasNext()
    {
        switch ( strategie )
        {
            case SUB:
                return currentValue == UNSET || currentValue > stopAt;
            default:
                return currentValue < stopAt;
        }
    }

    @Override
    public void remove()
    {
        // not implemented
    }

    public void reset()
    {
        currentValue = UNSET;
        stop = false;
    }

    @Override
    public IterateModel clone()
        throws CloneNotSupportedException
    {
        final IterateModel clone = (IterateModel) super.clone();
        clone.reset();

        return clone;
    }

    public static class IterateModelBuilder
    {
        private int startAt = 0;

        private int stopAt = Integer.MAX_VALUE;

        private int defaultIncrement = 1;

        private IterateStrategie iterateStrategie;

        private IncreaseIncrementStrategie increaseIncrementStrategie;

        public static IterateModelBuilder create()
        {
            return new IterateModelBuilder();
        }

        public final IterateModelBuilder startAt( final int startAt )
        {
            this.startAt = startAt;
            return this;
        }

        public final IterateModelBuilder stopAt( final int stopAt )
        {
            this.stopAt = stopAt;
            return this;
        }

        public final IterateModelBuilder setIncrement( final int increment )
        {
            this.defaultIncrement = increment;
            return this;
        }

        public final IterateModelBuilder setIterateStrategie( final IterateStrategie iterateStrategie )
        {
            this.iterateStrategie = iterateStrategie;
            return this;
        }

        public final IterateModelBuilder setIncreaseIncrementStrategie( final IncreaseIncrementStrategie increaseIncrementStrategie )
        {
            this.increaseIncrementStrategie = increaseIncrementStrategie;
            return this;
        }

        public IterateModel build()
        {
            IterateModel iterateModel = new IterateModel();
            iterateModel.startAt( startAt );
            iterateModel.stopAt( stopAt );
            iterateModel.setIncrement( defaultIncrement );
            if ( iterateStrategie == null )
            {
                iterateStrategie = IterateStrategie.ADD;
            }
            if ( increaseIncrementStrategie == null )
            {
                increaseIncrementStrategie = IncreaseIncrementStrategie.AGGRESSIV;
            }

            iterateModel.setIterateStrategie( iterateStrategie );
            iterateModel.setIncreaseIncrementStrategie( increaseIncrementStrategie );

            return iterateModel;
        }
    }

}
