package burp.ui.renderer;

import burp.BurpExtender;
import burp.model.FingerPrintRule;
import burp.ui.FingerConfigTab;
import burp.util.UiUtils;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import java.awt.*;


public class ButtonRenderer extends JPanel implements TableCellRenderer {
    private static final Icon EDIT_ICON = UiUtils.getImageIcon("/icon/editButton.png");
    private static final Icon DELETE_ICON = UiUtils.getImageIcon("/icon/deleteButton.png");
    private static final Icon OPEN_ICON = UiUtils.getImageIcon("/icon/openButtonIcon.png");
    private static final Icon CLOSE_ICON = UiUtils.getImageIcon("/icon/shutdownButtonIcon.png");
    private final JButton editButton;
    private final JButton deleteButton;
    private final JButton toggleButton;

    public ButtonRenderer() {
        setLayout(new FlowLayout(FlowLayout.CENTER, 5, 0));
        editButton = createButton(EDIT_ICON);
        deleteButton = createButton(DELETE_ICON);
        toggleButton = createButton(OPEN_ICON);
        add(toggleButton);
        add(editButton);
        add(deleteButton);
        setOpaque(true); // 设置为不透明，这样背景颜色变更才会生效
    }

    private JButton createButton(Icon icon) {
        JButton button = new JButton(icon);
        button.setPreferredSize(new Dimension(17, 17));
        button.setMargin(new Insets(0, 0, 0, 0)); // 设置按钮边距为0
        // 设置按钮边界为透明，以免在不同的LookAndFeel下显示不一致
        button.setBorder(BorderFactory.createEmptyBorder());
        button.setContentAreaFilled(false);
        return button;
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        // 注意：这里使用传入的 `row` 参数，而不是 `table.getSelectedRow()`
        int modelRow = table.convertRowIndexToModel(row); // 转换为模型索引
        int dataIndex = FingerConfigTab.tableToModelIndexMap.get(modelRow); // 使用模型索引查找原始数据列表中的索引

        FingerPrintRule rule = BurpExtender.fingerprintRules.get(dataIndex);
        if (rule.getIsOpen()) {
            toggleButton.setIcon(OPEN_ICON); // 如果规则是打开状态，设置为打开图标
        } else {
            toggleButton.setIcon(CLOSE_ICON); // 如果规则是关闭状态，设置为关闭图标
        }

        // 设置背景色，根据是否选中来决定
        if (isSelected) {
            setBackground(table.getSelectionBackground());
        } else {
            setBackground(table.getBackground());
        }
        // 重要：这里要返回包含正确图标的 toggleButton
        return this;
    }

}
