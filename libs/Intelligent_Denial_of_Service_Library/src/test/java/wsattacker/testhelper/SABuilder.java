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
package wsattacker.testhelper;

import wsattacker.library.intelligentdos.common.SuccessfulAttack;
import wsattacker.library.intelligentdos.dos.CoerciveParsing;
import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.intelligentdos.dos.HashCollision;
import wsattacker.library.intelligentdos.dos.XmlAttributeCount;
import wsattacker.library.intelligentdos.dos.XmlElementCount;
import wsattacker.library.intelligentdos.dos.XmlEntityExpansion;
import wsattacker.library.intelligentdos.dos.XmlExternalEntity;
import wsattacker.library.intelligentdos.dos.XmlOverlongNames;
import wsattacker.library.intelligentdos.dos.XmlOverlongNames.For;
import wsattacker.library.intelligentdos.helper.CommonParamItem;
import wsattacker.library.intelligentdos.helper.IterateModel;
import wsattacker.library.intelligentdos.position.Position;
import wsattacker.plugin.dos.dosExtension.attackClasses.hashDos.CollisionInterface;

/**
 * @author Christian Altmeier
 */
public class SABuilder
{
    private DoSAttack doSAttack;

    private CommonParamItem paramItem;

    private PayloadPosition payloadPosition;

    private Position position;

    private SABuilder()
    {
    }

    public static SABuilder CoerciveParsing( int numberOfTags )
    {
        SABuilder builder = new SABuilder();
        CoerciveParsing coerciveParsing = new CoerciveParsing();
        coerciveParsing.setNumberOfTagsIterator( IterateModel.custom().startAt( numberOfTags ).build() );
        coerciveParsing.nextParam();
        builder.doSAttack = coerciveParsing;

        return builder;
    }

    public static SABuilder XmlElementCount( int numberOfElements )
    {
        SABuilder builder = new SABuilder();
        XmlElementCount xmlElementCount = new XmlElementCount();
        xmlElementCount.setNumberOfElementsIterator( IterateModel.custom().startAt( numberOfElements ).build() );
        xmlElementCount.nextParam();
        builder.doSAttack = xmlElementCount;

        return builder;
    }

    public static SABuilder XmlAttributeCount( int numberOfAttributes, String name )
    {
        SABuilder builder = new SABuilder();
        XmlAttributeCount xmlAttributeCount = new XmlAttributeCount();
        xmlAttributeCount.setNumberOfAttributesIterator( IterateModel.custom().startAt( numberOfAttributes ).build() );
        xmlAttributeCount.setNames( new String[] { name } );
        xmlAttributeCount.nextParam();

        builder.doSAttack = xmlAttributeCount;

        return builder;
    }

    public static SABuilder XmlEntityExpansion( int numberOfElements, int numberOfEntities )
    {
        SABuilder builder = new SABuilder();
        XmlEntityExpansion xmlEntityExpansion = new XmlEntityExpansion();
        xmlEntityExpansion.setNumberOfEntityElementsIterator( IterateModel.custom().startAt( numberOfElements ).build() );
        xmlEntityExpansion.setNumberOfEntitiesIterator( IterateModel.custom().startAt( numberOfEntities ).build() );
        xmlEntityExpansion.nextParam();
        builder.doSAttack = xmlEntityExpansion;

        return builder;
    }

    public static SABuilder XmlExternalEntity( String externalEntity )
    {
        SABuilder builder = new SABuilder();
        XmlExternalEntity xmlExternalEntity = new XmlExternalEntity();
        xmlExternalEntity.setExternalEntities( new String[] { externalEntity } );
        xmlExternalEntity.nextParam();
        builder.doSAttack = xmlExternalEntity;

        return builder;
    }

    public static SABuilder HashCollision( CollisionInterface collisionGenerator, int numberOfAttributes,
                                           Boolean useNamespace )
    {
        SABuilder builder = new SABuilder();
        HashCollision hashCollision = new HashCollision();
        hashCollision.setCollisionGenerators( new CollisionInterface[] { collisionGenerator } );
        hashCollision.setNumberOfCollisionsIterator( IterateModel.custom().startAt( numberOfAttributes ).build() );
        hashCollision.setUseNamespace( new Boolean[] { useNamespace } );
        hashCollision.nextParam();
        builder.doSAttack = hashCollision;

        return builder;
    }

    public static SABuilder XmlOverlongNames( For overlongFor, int lengthOfString, int numberOfElements )
    {
        SABuilder builder = new SABuilder();
        XmlOverlongNames xmlOverlongNames = new XmlOverlongNames();
        xmlOverlongNames.setLengthOfStringsIterator( IterateModel.custom().startAt( lengthOfString ).build() );
        xmlOverlongNames.setNumberOfElementsIterator( IterateModel.custom().startAt( numberOfElements ).build() );
        xmlOverlongNames.setOverlongNamesFor( new For[] { overlongFor } );
        xmlOverlongNames.nextParam();
        builder.doSAttack = xmlOverlongNames;

        return builder;
    }

    public SABuilder withPayloadPosition( PayloadPosition payloadPosition )
    {
        this.payloadPosition = payloadPosition;
        return this;
    }

    public SABuilder withPosition( Position position )
    {
        this.position = position;
        return this;
    }

    public SABuilder withParamItem( CommonParamItem paramItem )
    {
        this.paramItem = paramItem;
        return this;
    }

    public SuccessfulAttack build()
    {
        SuccessfulAttack successfulAttack = new SuccessfulAttack( doSAttack, paramItem );
        successfulAttack.setPayloadPosition( payloadPosition );
        successfulAttack.setPosition( position );

        return successfulAttack;
    }
}
