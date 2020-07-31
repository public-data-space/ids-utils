package de.fraunhofer.fokus.ids.utils;

import de.fraunhofer.fokus.ids.utils.models.IDSMessage;
import de.fraunhofer.iais.eis.Message;
import de.fraunhofer.iais.eis.ids.jsonld.Serializer;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import org.apache.commons.io.IOUtils;
import org.eclipse.jetty.http.MultiPartFormInputStream;

import javax.servlet.http.Part;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Optional;

/**
 * @author Vincent Bohlen, vincent.bohlen@fokus.fraunhofer.de
 */
public class IDSMessageParser {
    private static Logger LOGGER = LoggerFactory.getLogger(IDSMessageParser.class.getName());
    private static final String SEPARATOR = "msgpart";
    private static Serializer serializer = new Serializer();

    public static Optional<IDSMessage> parse(String requestMessage){

        InputStream messageBodyStream = new ByteArrayInputStream(requestMessage.getBytes(Charset.defaultCharset()));

        MultiPartFormInputStream multiPartInputStream = new MultiPartFormInputStream(messageBodyStream, "multipart/form-data; boundary="+SEPARATOR, null, null);
        try {
            Part header = multiPartInputStream.getPart("header");
            Part payload = multiPartInputStream.getPart("payload");
            String payloadString = "";
            String headerString = "";

            if(header != null) {
                headerString = IOUtils.toString(multiPartInputStream.getPart("header").getInputStream(), Charset.defaultCharset());
            }
            if(payload != null) {
                payloadString = IOUtils.toString(multiPartInputStream.getPart("payload").getInputStream(), Charset.defaultCharset());
            }
            Message idsMessage = null;
            try{
                idsMessage = serializer.deserialize(headerString, Message.class);
            } catch( Exception e){
                LOGGER.error("Could not deserialize message.");
            }
            return Optional.of(new IDSMessage(idsMessage, payloadString));
        } catch (IOException e) {
            LOGGER.error(e);
        }
        return Optional.empty();
    }
}
