package burp.ui.renderer;

import burp.util.UiUtils;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class IsJsFindUrlRenderer extends DefaultTableCellRenderer {
    // 预加载并缓存图标
    private final Icon findUrlIcon = UiUtils.getImageIcon("/icon/findUrlFromJS.png", 15, 15);
    private final Icon noFindUrlIcon = UiUtils.getImageIcon("/icon/noFindUrlFromJS.png", 15, 15);

    public IsJsFindUrlRenderer() {
        setHorizontalAlignment(CENTER); // 设置居中
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        // 调用父类以保留默认行为（例如文本，背景色和前景色的选择）
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        // 设置文本为空，因为我们只显示图标
        setText("");

        // 根据单元格值设置相应图标
        if (value instanceof String) {
            String stringValue = (String) value;
            if (stringValue.equalsIgnoreCase("N")) {
                setIcon(noFindUrlIcon);
            } else {
                setIcon(null);
                setText(stringValue); // 如果有其他值，显示文本
            }
        } else {
            setIcon(null); // 如果值不是String类型，则不显示图标或文本
        }

        return this;
    }
}
