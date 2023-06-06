import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Base64;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class SerializationUtils {

    /**
     * Serialize an object to a string.
     *
     * @param object the object to serialize
     * @return the serialized object as a string
     * @throws Exception if the object cannot be serialized
     */
    public static String serialize(Serializable object) throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(object);
        objectOutputStream.flush();
        return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
    }

    /**
     * Deserialize an object from a string.
     *
     * @param serializedObject the serialized object as a string
     * @return the deserialized object
     * @throws Exception if the object cannot be deserialized
     */
    public static Object deserialize(String serializedObject) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(serializedObject);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        return objectInputStream.readObject();
    }

    /**
     * Serialize a JPBC element to a string.
     *
     * @param element the element to serialize
     * @return the serialized element as a string
     */
    public static String serializeElement(Element element) {
        Field field = element.getField();
        String pairingString = field.toString();
        String elementString = Base64.getEncoder().encodeToString(element.toBytes());
        return pairingString + ":" + elementString;
    }

    /**
     * Deserialize a JPBC element from a string.
     *
     * @param serializedElement the serialized element as a string
     * @return the deserialized element
     */
    public static Element deserializeElement(String serializedElement) {
        String[] parts = serializedElement.split(":");
        String pairingString = parts[0];
        String elementString = parts[1];
        Pairing pairing = PairingFactory.getPairing(pairingString);
        byte[] bytes = Base64.getDecoder().decode(elementString);
        return pairing.getG1().newElementFromBytes(bytes);
    }
}
