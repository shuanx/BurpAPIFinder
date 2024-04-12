package burp.ui.renderer;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * @author： shaun
 * @create： 2024/3/27 21:31
 * @description：TODO
 */
public class CenterTableCellRenderer extends DefaultTableCellRenderer {
    public CenterTableCellRenderer() {
        setHorizontalAlignment(JLabel.CENTER); // 设置水平对齐为居中
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        return this;
    }
}
