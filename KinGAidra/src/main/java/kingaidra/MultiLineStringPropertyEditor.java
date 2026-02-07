package kingaidra;

import java.awt.Component;
import java.beans.PropertyEditorSupport;
import java.util.Objects;

import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

public final class MultiLineStringPropertyEditor extends PropertyEditorSupport {

    private final JTextArea text_area = new JTextArea(10, 80);
    private final JScrollPane scroll_panel = new JScrollPane(text_area);

    private boolean updating_from_model = false;

    public MultiLineStringPropertyEditor() {
        text_area.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { syncFromUi(); }
            @Override public void removeUpdate(DocumentEvent e) { syncFromUi(); }
            @Override public void changedUpdate(DocumentEvent e) { syncFromUi(); }
        });
    }

    @Override
    public boolean supportsCustomEditor() {
        return true;
    }

    @Override
    public Component getCustomEditor() {
        return scroll_panel;
    }

    @Override
    public void setValue(Object value) {
        String s = (value == null) ? "" : String.valueOf(value);

        updating_from_model = true;
        try {
            if (!Objects.equals(text_area.getText(), s)) {
                text_area.setText(s);
                text_area.setCaretPosition(0);
            }
            super.setValue(s);
        }
        finally {
            updating_from_model = false;
        }
    }

    @Override
    public Object getValue() {
        return super.getValue();
    }

    @Override
    public void setAsText(String text) throws IllegalArgumentException {
        setValue(text);
        firePropertyChange();
    }

    private void syncFromUi() {
        if (updating_from_model) {
            return;
        }

        String new_text = text_area.getText();
        String old_text = (String) super.getValue();

        if (!Objects.equals(old_text, new_text)) {
            super.setValue(new_text);
            firePropertyChange();
        }
    }
}
