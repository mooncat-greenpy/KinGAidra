package kingaidra.chat.gui;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Locale;

import javax.imageio.ImageIO;

import net.sourceforge.plantuml.FileFormat;
import net.sourceforge.plantuml.FileFormatOption;
import net.sourceforge.plantuml.SourceStringReader;

public final class PlantUmlRenderer {
    private static final String PLANTUML_SECURITY_PROFILE = "PLANTUML_SECURITY_PROFILE";

    static {
        if (System.getProperty(PLANTUML_SECURITY_PROFILE) == null) {
            System.setProperty(PLANTUML_SECURITY_PROFILE, "SANDBOX");
        }
    }

    private PlantUmlRenderer() {
    }

    public static String force_smetana(String source) {
        String s = source == null ? "" : source;
        String s_lower = s.toLowerCase(Locale.ROOT);
        if (!s_lower.contains("@start")) {
            s = "@startuml\n" + s + "\n@enduml\n";
            s_lower = s.toLowerCase(Locale.ROOT);
        }

        s = s.replaceAll("(?im)^\\s*!pragma\\s+layout\\s+\\S+\\s*$", "!pragma layout smetana");
        if (!s.toLowerCase(Locale.ROOT).contains("!pragma layout smetana")) {
            s = s.replaceFirst("(?im)^\\s*@start\\w*.*$", "$0\n!pragma layout smetana");
        }
        return s;
    }

    public static BufferedImage render_plantuml_png(String plantuml_source) throws IOException {
        String src = force_smetana(plantuml_source);
        SourceStringReader reader = new SourceStringReader(src);
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            reader.outputImage(out, new FileFormatOption(FileFormat.PNG));
            try (ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray())) {
                BufferedImage img = ImageIO.read(in);
                if (img == null) {
                    throw new IOException("PlantUML PNG decode failed");
                }
                return img;
            }
        }
    }
}
