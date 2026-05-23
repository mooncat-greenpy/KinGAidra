package kingaidra.ai.convo;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import db.BinaryField;
import db.DBHandle;
import db.DBRecord;
import db.Field;
import db.RecordIterator;
import db.Schema;
import db.StringField;
import db.Table;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelByScript;
import kingaidra.ai.model.ModelType;
import kingaidra.ghidra.GhidraUtil;

public class ConversationContainerGhidraProgram implements ConversationContainer {

    private static final String CONVO_TABLE_NAME_V1 = "KinGAidra_Conversation";
    private static final String CONVO_TABLE_NAME_V2 = "KinGAidra_Conversation_V2";
    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();
    private Program program;
    private GhidraUtil ghidra;

    public ConversationContainerGhidraProgram(Program program, GhidraUtil ghidra) {
        this.program = program;
        this.ghidra = ghidra;
    }

    private DBHandle get_db_handle() {
        if (program == null) {
            return null;
        }
        ProgramDB program_db = (ProgramDB) program;
        return program_db.getDBHandle();
    }

    private Object legacy_deserialize_stored_object(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            return in.readObject();
        } catch (IOException | ClassNotFoundException e) {
        }
        return null;
    }

    private <T> T legacy_deserialize_stored_object(byte[] bytes, Class<T> expected_type) {
        Object obj = legacy_deserialize_stored_object(bytes);
        if (!expected_type.isInstance(obj)) {
            return null;
        }
        return expected_type.cast(obj);
    }

    private static final int RECORD_UUID_INDEX_V1 = 0;
    private static final int RECORD_TYPE_INDEX_V1 = 1;
    private static final int RECORD_MODEL_INDEX_V1 = 2;
    private static final int RECORD_CREATED_INDEX_V1 = 3;
    private static final int RECORD_UPDATED_INDEX_V1 = 4;
    private static final int RECORD_MESSAGES_INDEX_V1 = 5;
    private static final int RECORD_ADDRESSES_INDEX_V1 = 6;
    private static final Schema CONVERSATION_SCHEMA_V1 =
            new Schema(1, StringField.INSTANCE, "Conversation",
                    new Field[] {StringField.INSTANCE, StringField.INSTANCE, BinaryField.INSTANCE,
                            StringField.INSTANCE, StringField.INSTANCE,
                            BinaryField.INSTANCE, BinaryField.INSTANCE,},
                    new String[] {"UUID", "Type", "Model", "Created", "Updated",
                            "Messages", "Addresses"});

    private static final int RECORD_UUID_INDEX_V2 = 0;
    private static final int RECORD_TYPE_INDEX_V2 = 1;
    private static final int RECORD_MODEL_CLASS_INDEX_V2 = 2;
    private static final int RECORD_MODEL_NAME_INDEX_V2 = 3;
    private static final int RECORD_MODEL_SCRIPT_INDEX_V2 = 4;
    private static final int RECORD_MODEL_TYPE_INDEX_V2 = 5;
    private static final int RECORD_CREATED_INDEX_V2 = 6;
    private static final int RECORD_UPDATED_INDEX_V2 = 7;
    private static final int RECORD_MESSAGES_JSON_INDEX_V2 = 8;
    private static final int RECORD_ADDRESSES_JSON_INDEX_V2 = 9;
    private static final Schema CONVERSATION_SCHEMA_V2 =
            new Schema(2, StringField.INSTANCE, "Conversation",
                    new Field[] {StringField.INSTANCE, StringField.INSTANCE, StringField.INSTANCE,
                            StringField.INSTANCE, StringField.INSTANCE, StringField.INSTANCE,
                            StringField.INSTANCE, StringField.INSTANCE, StringField.INSTANCE,
                            StringField.INSTANCE,},
                    new String[] {"UUID", "Type", "ModelClass", "ModelName", "ModelScript",
                            "ModelType", "Created", "Updated", "MessagesJson",
                            "AddressesJson"});

    private boolean has_schema(Table table, Schema schema) {
        return table != null && table.getSchema().equals(schema);
    }

    private Table get_v1_table() {
        DBHandle db_handle = get_db_handle();
        if (db_handle == null) {
            return null;
        }
        return db_handle.getTable(CONVO_TABLE_NAME_V1);
    }

    private Table get_v2_table() {
        DBHandle db_handle = get_db_handle();
        if (db_handle == null) {
            return null;
        }
        return db_handle.getTable(CONVO_TABLE_NAME_V2);
    }

    private Table create_or_open_v2_table() {
        DBHandle db_handle = get_db_handle();
        if (db_handle == null) {
            return null;
        }
        try {
            Table table = db_handle.getTable(CONVO_TABLE_NAME_V2);
            if (table == null) {
                table = db_handle.createTable(CONVO_TABLE_NAME_V2, CONVERSATION_SCHEMA_V2);
            }
            return table;
        } catch (IOException e) {
            return null;
        }
    }

    private void add_ids_from_table(Table table, int uuid_index, Set<UUID> uuids) {
        try {
            RecordIterator itr = table.iterator();
            while (itr.hasNext()) {
                DBRecord record = itr.next();
                uuids.add(UUID.fromString(record.getString(uuid_index)));
            }
        } catch (IllegalArgumentException | IOException e) {
        }
    }

    public UUID[] get_ids() {
        LinkedHashSet<UUID> uuids = new LinkedHashSet<>();

        Table v2_table = get_v2_table();
        if (v2_table != null && has_schema(v2_table, CONVERSATION_SCHEMA_V2)) {
            add_ids_from_table(v2_table, RECORD_UUID_INDEX_V2, uuids);
        }

        Table v1_table = get_v1_table();
        if (v1_table != null && has_schema(v1_table, CONVERSATION_SCHEMA_V1)) {
            add_ids_from_table(v1_table, RECORD_UUID_INDEX_V1, uuids);
        }

        return uuids.toArray(new UUID[] {});
    }

    public Conversation get_convo(UUID id) {
        Conversation convo = get_v2_convo(id);
        if (convo != null) {
            return convo;
        }
        return get_legacy_v1_convo(id);
    }

    private Conversation get_v2_convo(UUID id) {
        Table table = get_v2_table();
        if (table == null || !has_schema(table, CONVERSATION_SCHEMA_V2)) {
            return null;
        }
        try {
            DBRecord record = table.getRecord(new StringField(id.toString()));
            if (record == null) {
                return null;
            }
            return get_convo_v2(record);
        } catch (IOException e) {
            return null;
        }
    }

    private Conversation get_legacy_v1_convo(UUID id) {
        Table v1_table = get_v1_table();
        if (v1_table == null || !has_schema(v1_table, CONVERSATION_SCHEMA_V1)) {
            return null;
        }
        try {
            DBRecord record = v1_table.getRecord(new StringField(id.toString()));
            if (record == null) {
                return null;
            }

            Conversation convo = get_legacy_v1_convo(record);
            if (convo == null) {
                return null;
            }

            migrate_legacy_v1_record(id, convo);
            return convo;
        } catch (IOException e) {
            return null;
        }
    }

    private void migrate_legacy_v1_record(UUID id, Conversation convo) {
        int tid = program.startTransaction("KinGAidra database migration");
        boolean success = false;
        try {
            Table v1_table = get_v1_table();
            Table v2_table = create_or_open_v2_table();
            if (v1_table != null && v2_table != null &&
                    add_convo_v2_record(v2_table, convo)) {
                v1_table.deleteRecord(new StringField(id.toString()));
                success = true;
            }
        } catch (IOException e) {
        } finally {
            program.endTransaction(tid, success);
        }
    }

    private Conversation get_legacy_v1_convo(DBRecord record) {
        String uuid = record.getString(RECORD_UUID_INDEX_V1);
        ConversationType type;
        try {
            type = ConversationType.valueOf(record.getString(RECORD_TYPE_INDEX_V1));
        } catch (IllegalArgumentException | NullPointerException e) {
            return null;
        }
        Model model = legacy_deserialize_stored_object(record.getBinaryData(RECORD_MODEL_INDEX_V1),
                Model.class);
        if (model == null) {
            return null;
        }
        String created = record.getString(RECORD_CREATED_INDEX_V1);
        String updated = record.getString(RECORD_UPDATED_INDEX_V1);
        Message[] msgs = legacy_deserialize_stored_object(record.getBinaryData(RECORD_MESSAGES_INDEX_V1),
                Message[].class);
        if (msgs == null) {
            return null;
        }
        Long[] addrs_value = legacy_deserialize_stored_object(
                record.getBinaryData(RECORD_ADDRESSES_INDEX_V1), Long[].class);
        if (addrs_value == null) {
            return null;
        }

        List<Address> addrs = new LinkedList<>();
        for (long addr_value : addrs_value) {
            addrs.add(ghidra.get_addr(addr_value));
        }
        Conversation convo = new Conversation(uuid, type, model, created, updated, msgs, addrs.toArray(new Address[]{}));

        return convo;
    }

    private Conversation get_convo_v2(DBRecord record) {
        try {
            String uuid = record.getString(RECORD_UUID_INDEX_V2);
            ConversationType type =
                    ConversationType.valueOf(record.getString(RECORD_TYPE_INDEX_V2));
            Model model = get_model_v2(record);
            if (model == null) {
                return null;
            }
            String created = record.getString(RECORD_CREATED_INDEX_V2);
            String updated = record.getString(RECORD_UPDATED_INDEX_V2);
            Message[] msgs = messages_from_json(record.getString(RECORD_MESSAGES_JSON_INDEX_V2));
            Address[] addrs = addresses_from_json(record.getString(RECORD_ADDRESSES_JSON_INDEX_V2));
            return new Conversation(uuid, type, model, created, updated, msgs, addrs);
        } catch (IllegalArgumentException | IOException e) {
        }
        return null;
    }

    private Model get_model_v2(DBRecord record) {
        String model_class = record.getString(RECORD_MODEL_CLASS_INDEX_V2);
        String name = record.getString(RECORD_MODEL_NAME_INDEX_V2);
        String script = record.getString(RECORD_MODEL_SCRIPT_INDEX_V2);
        String type_value = record.getString(RECORD_MODEL_TYPE_INDEX_V2);
        if ("ModelByScript".equals(model_class)) {
            ModelByScript model = new ModelByScript(name, script, true);
            if (type_value != null) {
                try {
                    model.set_type(ModelType.valueOf(type_value));
                } catch (IllegalArgumentException e) {
                }
            }
            return model;
        }
        return null;
    }

    private Message[] messages_from_json(String messages_json) throws IOException {
        if (messages_json == null || messages_json.isEmpty()) {
            return new Message[] {};
        }
        List<Map<String, Object>> msg_maps = JSON_MAPPER.readValue(messages_json,
                new TypeReference<List<Map<String, Object>>>() {});
        List<Message> msgs = new ArrayList<>(msg_maps.size());
        for (Map<String, Object> msg_map : msg_maps) {
            Message msg = Message.from_map(msg_map);
            if (msg != null) {
                msgs.add(msg);
            }
        }
        return msgs.toArray(new Message[] {});
    }

    private Address[] addresses_from_json(String addresses_json) throws IOException {
        if (addresses_json == null || addresses_json.isEmpty()) {
            return new Address[] {};
        }
        List<Long> addr_values =
                JSON_MAPPER.readValue(addresses_json, new TypeReference<List<Long>>() {});
        List<Address> addrs = new LinkedList<>();
        for (Long addr_value : addr_values) {
            if (addr_value == null) {
                continue;
            }
            Address addr = ghidra.get_addr(addr_value);
            if (addr != null) {
                addrs.add(addr);
            }
        }
        return addrs.toArray(new Address[] {});
    }

    private boolean add_convo_v2_record(Table table, Conversation convo) {
        DBRecord record;
        try {
            record = create_convo_v2_record(convo);
        } catch (IOException e) {
            return false;
        }
        try {
            table.putRecord(record);
            return true;
        } catch (IOException e) {
        }
        return false;
    }

    private DBRecord create_convo_v2_record(Conversation convo) throws IOException {
        DBRecord record =
                CONVERSATION_SCHEMA_V2.createRecord(new StringField(convo.get_uuid().toString()));
        record.setString(RECORD_UUID_INDEX_V2, convo.get_uuid().toString());
        record.setString(RECORD_TYPE_INDEX_V2, convo.get_type().toString());
        set_model_v2(record, convo.get_model());
        record.setString(RECORD_CREATED_INDEX_V2, convo.get_created());
        record.setString(RECORD_UPDATED_INDEX_V2, convo.get_updated());
        record.setString(RECORD_MESSAGES_JSON_INDEX_V2, messages_to_json(convo));
        record.setString(RECORD_ADDRESSES_JSON_INDEX_V2, addresses_to_json(convo.get_addrs()));
        return record;
    }

    private void set_model_v2(DBRecord record, Model model) {
        String model_class = model instanceof ModelByScript ? "ModelByScript" : model.getClass().getName();
        record.setString(RECORD_MODEL_CLASS_INDEX_V2, model_class);
        record.setString(RECORD_MODEL_NAME_INDEX_V2, ((ModelByScript) model).get_name());
        record.setString(RECORD_MODEL_SCRIPT_INDEX_V2, ((ModelByScript) model).get_script());
        record.setString(RECORD_MODEL_TYPE_INDEX_V2, model.get_type().toString());
    }

    private String messages_to_json(Conversation convo) throws IOException {
        List<Message> msgs = new ArrayList<>(convo.get_msgs_len());
        for (int i = 0; i < convo.get_msgs_len(); i++) {
            msgs.add(new Message(
                    convo.get_role(i),
                    convo.get_msg(i),
                    convo.get_tool_call_id(i),
                    convo.get_tool_calls(i)));
        }
        return JSON_MAPPER.writeValueAsString(msgs);
    }

    private String addresses_to_json(Address[] addrs) throws IOException {
        if (addrs == null) {
            return "[]";
        }
        List<Long> addr_values = new ArrayList<>(addrs.length);
        for (Address addr : addrs) {
            if (addr != null) {
                addr_values.add(addr.getOffset());
            }
        }
        return JSON_MAPPER.writeValueAsString(addr_values);
    }

    public void add_convo(Conversation convo) {
        int tid = program.startTransaction("KinGAidra database");
        boolean success = false;
        try {
            Table table = create_or_open_v2_table();
            if (table == null) {
                return;
            }
            success = add_convo_v2_record(table, convo);
        } finally {
            program.endTransaction(tid, success);
        }
    }

    public void del_convo(UUID id) {
        int tid = program.startTransaction("KinGAidra database");
        boolean success = false;
        try {
            boolean deleted = false;

            Table v2_table = get_v2_table();
            if (v2_table != null && has_schema(v2_table, CONVERSATION_SCHEMA_V2)) {
                deleted |= v2_table.deleteRecord(new StringField(id.toString()));
            }

            Table v1_table = get_v1_table();
            if (v1_table != null && has_schema(v1_table, CONVERSATION_SCHEMA_V1)) {
                deleted |= v1_table.deleteRecord(new StringField(id.toString()));
            }

            success = deleted;
        } catch (IOException e) {
        } finally {
            program.endTransaction(tid, success);
        }
    }

}
