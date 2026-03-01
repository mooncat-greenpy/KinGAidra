package kingaidra.ai.convo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import db.BinaryField;
import db.DBHandle;
import db.DBRecord;
import db.Field;
import db.Schema;
import db.StringField;
import db.RecordIterator;
import db.Table;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import kingaidra.ai.model.Model;
import kingaidra.ghidra.GhidraUtil;

public class ConversationContainerGhidraProgram implements ConversationContainer {

    private static final String CONVO_TABLE_NAME = "KinGAidra_Conversation";
    private Program program;
    private GhidraUtil ghidra;

    public ConversationContainerGhidraProgram(Program program, GhidraUtil ghidra) {
        this.program = program;
        this.ghidra = ghidra;
    }

    private Table get_table(String name) {
        if (program == null) {
            return null;
        }
        ProgramDB program_db = (ProgramDB) program;
        DBHandle db_handle = program_db.getDBHandle();
        return db_handle.getTable(name);
    }

    private Table create_or_open_table(String name, Schema schema) {
        if (program == null) {
            return null;
        }
        ProgramDB program_db = (ProgramDB) program;
        DBHandle db_handle = program_db.getDBHandle();
        try {
            Table table = db_handle.getTable(name);
            if (table == null) {
                table = db_handle.createTable(name, schema);
            }
            return table;
        } catch (IOException e) {
        }
        return null;
    }

    private Table create_new_table(String name, Schema schema) {
        if (program == null) {
            return null;
        }
        ProgramDB program_db = (ProgramDB) program;
        DBHandle db_handle = program_db.getDBHandle();
        try {
            Table table = db_handle.getTable(name);
            if (table == null) {
                table = db_handle.createTable(name, schema);
            } else {
                db_handle.deleteTable(name);
                table = db_handle.createTable(name, schema);
            }
            return table;
        } catch (IOException e) {
        }
        return null;
    }

    private static byte[] obj_to_bytes(Object obj) {
        ByteArrayOutputStream byte_out = new ByteArrayOutputStream();
        ObjectOutputStream out;
        try {
            out = new ObjectOutputStream(byte_out);
            out.writeObject(obj);
            return byte_out.toByteArray();
        } catch (IOException e) {
        }
        return null;
    }

    private static Object bytes_to_obj(byte[] bytes) {
        ByteArrayInputStream byte_in = new ByteArrayInputStream(bytes);
        ObjectInputStream in;
        try {
            in = new ObjectInputStream(byte_in);
            return in.readObject();
        } catch (IOException | ClassNotFoundException e) {
        }
        return null;
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

    public UUID[] get_ids() {
        Table table = get_table(CONVO_TABLE_NAME);
        if (table == null) {
            return new UUID[] {};
        }
        List<UUID> uuids = new ArrayList<>(table.getRecordCount());
        try {
            RecordIterator itr = table.iterator();
            while (itr.hasNext()) {
                DBRecord record = itr.next();
                String uuid = record.getString(RECORD_UUID_INDEX_V1);
                uuids.add(UUID.fromString(uuid));
            }
        } catch (IOException e) {
            return new UUID[] {};
        }

        return uuids.toArray(new UUID[] {});
    }

    public Conversation get_convo(UUID id) {
        Table table = get_table(CONVO_TABLE_NAME);
        if (table == null) {
            return null;
        }
        DBRecord record;
        try {
            record = table.getRecord(new StringField(id.toString()));
        } catch (IOException e) {
            return null;
        }
        if (record == null) {
            return null;
        }
        if (!record.hasSameSchema(CONVERSATION_SCHEMA_V1)) {
            return null;
        }

        String uuid = record.getString(RECORD_UUID_INDEX_V1);
        ConversationType type = ConversationType.valueOf(record.getString(RECORD_TYPE_INDEX_V1));
        Model model = (Model) bytes_to_obj(record.getBinaryData(RECORD_MODEL_INDEX_V1));
        if (model == null) {
            return null;
        }
        String created = record.getString(RECORD_CREATED_INDEX_V1);
        String updated = record.getString(RECORD_UPDATED_INDEX_V1);
        Object msgs_obj = bytes_to_obj(record.getBinaryData(RECORD_MESSAGES_INDEX_V1));
        if (!(msgs_obj instanceof Message[])) {
            return null;
        }
        Message[] msgs = (Message[]) msgs_obj;
        Long[] addrs_value = (Long[]) bytes_to_obj(record.getBinaryData(RECORD_ADDRESSES_INDEX_V1));
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

    public void add_convo(Conversation convo) {
        int tid = program.startTransaction("KinGAidra database");
        try {
            Table table = create_or_open_table(CONVO_TABLE_NAME, CONVERSATION_SCHEMA_V1);
            if (table == null) {
                return;
            }
            DBRecord record = CONVERSATION_SCHEMA_V1
                    .createRecord(new StringField(convo.get_uuid().toString()));
            record.setString(RECORD_UUID_INDEX_V1, convo.get_uuid().toString());
            record.setString(RECORD_TYPE_INDEX_V1, convo.get_type().toString());
            byte[] model_byte = obj_to_bytes(convo.get_model());
            if (model_byte == null) {
                return;
            }
            record.setBinaryData(RECORD_MODEL_INDEX_V1, model_byte);
            record.setString(RECORD_CREATED_INDEX_V1, convo.get_created());
            record.setString(RECORD_UPDATED_INDEX_V1, convo.get_updated());
            Message[] msgs = new Message[convo.get_msgs_len()];
            for (int i = 0; i < convo.get_msgs_len(); i++) {
                msgs[i] = new Message(
                        convo.get_role(i),
                        convo.get_msg(i),
                        convo.get_tool_call_id(i),
                        convo.get_tool_calls(i));
            }
            byte[] msgs_byte = obj_to_bytes(msgs);
            if (msgs_byte == null) {
                return;
            }
            record.setBinaryData(RECORD_MESSAGES_INDEX_V1, msgs_byte);
            List<Long> addrs = new ArrayList<>(convo.get_addrs().length);
            for (Address addr : convo.get_addrs()) {
                addrs.add(addr.getOffset());
            }
            byte[] addrs_byte = obj_to_bytes(addrs.toArray(new Long[] {}));
            if (addrs_byte == null) {
                return;
            }
            record.setBinaryData(RECORD_ADDRESSES_INDEX_V1, addrs_byte);

            try {
                table.putRecord(record);
            } catch (IOException e) {
            }
        } finally {
            program.endTransaction(tid, true);
        }
    }

    public void del_convo(UUID id) {
        int tid = program.startTransaction("KinGAidra database");
        try {
            Table table = create_or_open_table(CONVO_TABLE_NAME, CONVERSATION_SCHEMA_V1);
            if (table == null) {
                return;
            }
            try {
                table.deleteRecord(new StringField(id.toString()));
            } catch (IOException e) {
            }
        } finally {
            program.endTransaction(tid, true);
        }
    }

}
