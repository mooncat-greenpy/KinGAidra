package kingaidra.chat.gui;

import java.awt.image.BufferedImage;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PlantUmlRendererTest {

    @Test
    void test_force_smetana_adds_pragma() {
        String src = "Alice -> Bob: hello";
        String forced = PlantUmlRenderer.force_smetana(src);

        assertTrue(forced.contains("@startuml"));
        assertTrue(forced.contains("@enduml"));
        assertTrue(forced.toLowerCase().contains("!pragma layout smetana"));
    }

    @Test
    void test_force_smetana_replaces_existing_layout() {
        String src = "@startuml\n" +
                "!pragma layout elk\n" +
                "Alice -> Bob: hello\n" +
                "@enduml";
        String forced = PlantUmlRenderer.force_smetana(src);

        assertTrue(forced.contains("!pragma layout smetana"));
        assertFalse(forced.contains("!pragma layout elk"));
    }

    @Test
    void test_render_plantuml_png() throws Exception {
        String src = "@startuml\n" +
                "Alice -> Bob: hello\n" +
                "@enduml";
        BufferedImage img = PlantUmlRenderer.render_plantuml_png(src);

        assertNotNull(img);
        assertTrue(img.getWidth() > 0);
        assertTrue(img.getHeight() > 0);
    }
}
