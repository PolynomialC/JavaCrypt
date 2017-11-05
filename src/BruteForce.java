/*
* BruteForce.java
* Ascii character iterator
*
* @author J.Wharton
* 2017
*
*/

import javax.crypto.BadPaddingException;

public class BruteForce {

    public static StringBuilder generateStringFromInput(
            StringBuilder input,
            int stringLength,
            int minAsciiCode,
            int maxAsciiCode)
    throws BadPaddingException {
        StringBuilder output = new StringBuilder();

        if (input.toString().equals("")) {
            String minAsciiChar = Character.toString((char) (minAsciiCode));
            String outputString = String.format("%0" + stringLength + "d", 0).replace("0", minAsciiChar);
            output.append(outputString);
        } else {
            int currentIndex = ((input.length() - 1));  // initialise index get last character position
            int abortAfter = 200;
            int loopIterationCount = 0;

            while (true) {
                loopIterationCount += 1;
                if (loopIterationCount >= abortAfter) throw new RuntimeException("Aborted, too many iterations.");

                char currentChar = input.charAt(currentIndex);
                int currentAsciiCode = (int) currentChar;              //get ascii code for character
//                System.out.println("cIndex: " + currentIndex + " cChar: " + currentChar + " cAscii :" + currentAsciiCode);
//                System.out.println("maxAscii: " + maxAsciiCode);

                if (currentAsciiCode < maxAsciiCode) { // Current char can be iterated
                    int newAsciiCode = currentAsciiCode + 1;
                    char newChar = (char) newAsciiCode;
//                    System.out.println("Can Iterate! newChar : " + (newChar) + " newAscii :" + (newAsciiCode));
                    output.append(input.toString());
                    output.setCharAt(currentIndex, newChar);

                    if (currentIndex < (input.length() - 1)) { // we're not at the left most number
                        // we gotta replace any chars after currentIndex with (char) minAsciiCode
                       for (int i = (currentIndex + 1); i <= (output.length() - 1); i++) {
                           output.setCharAt(i, (char) minAsciiCode);
                       }

                    }

                    break;
                } else {
                    if (currentIndex == 0) {
                        throw new IllegalArgumentException("Already at last possible string.");
                    }

                    currentIndex -= 1;
                }
            }
        }

        return output;
    }


    public static boolean test(StringBuilder string, int storedString)
    {
        return false;
    }


    public static void main(String[] args) throws BadPaddingException {

        StringBuilder myString = new StringBuilder("0931324");
        int storedValue = 1;

        while (true) {
             myString = generateStringFromInput(myString, 7, 48, 57);
             System.out.println("String Builder output :" + (myString.toString()));

            if (test(myString, storedValue)) {
                System.out.println("Match Found!");
                break;
            }

        }
    }
}