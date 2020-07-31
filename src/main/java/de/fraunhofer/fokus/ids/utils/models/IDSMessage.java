package de.fraunhofer.fokus.ids.utils.models;

import de.fraunhofer.iais.eis.Message;

import java.util.Optional;

public class IDSMessage {

    Optional<Message> header;
    Optional<String> payload;

    public IDSMessage(Message header, String payload){
        if(header != null) {
            this.header = Optional.of(header);
        } else {
            this.header = Optional.empty();
        }
        if(payload != null && !payload.trim().equals("")) {
            this.payload = Optional.of(payload);
        } else {
            this.payload = Optional.empty();
        }
    }

    public void setHeader(Message header){
        if(header != null) {
            this.header = Optional.of(header);
        } else {
            this.header = Optional.empty();
        }
    }

    public void setPayload(String payload){
        if(payload != null && !payload.trim().equals("")) {
            this.payload = Optional.of(payload);
        } else {
            this.payload = Optional.empty();
        }
    }

    public Optional<Message> getHeader() {
        return header;
    }

    public Optional<String> getPayload() {
        return payload;
    }

}
