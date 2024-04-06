package burp.ui;


import burp.BurpExtender;
import burp.util.Constants;

import java.util.ArrayList;
import java.util.List;

public class ApiDocumentListTree {
    private ExtensionTab parent;
    private ExtensionTab.ApiTableData mainApiData;
    ArrayList<ExtensionTab.ApiTableData> subApiData;
    private Boolean expandStatus = false; // true = 展开, false = 收起

    public ApiDocumentListTree(ExtensionTab parent) {
        this.parent = parent;
    }

    public void setSubApiData(ArrayList<ExtensionTab.ApiTableData> subApiData) {
        this.subApiData = subApiData;
    }

    public ExtensionTab.ApiTableData getMainApiData() {
        return this.mainApiData;
    }

    public void setMainApiData(ExtensionTab.ApiTableData mainApiData) {
        this.mainApiData = mainApiData;
    }

    public Boolean getExpandStatus() {
        return this.expandStatus;
    }

    public void expand() {
        if (!this.expandStatus) {
            this.mainApiData.setTreeStatus(Constants.TREE_STATUS_EXPAND);

            int selfIndex = this.parent.getApiTable().getTableData().indexOf(this.mainApiData);

            for (int i = 0; i < subApiData.size(); i++) {
                ExtensionTab.ApiTableData data = subApiData.get(i);

                if (i != subApiData.size() - 1) {
                    data.setTreeStatus("┠");
                } else {
                    data.setTreeStatus("┗");
                }

                this.parent.getApiTable().getTableData().add(selfIndex + 1 + i, data);
            }
            // 通知监听器，从selfIndex + 1 到 selfIndex + subApiData.size()的行已经被插入
            parent.fireTableRowsInserted(selfIndex + 1, selfIndex + subApiData.size());
        }
        this.expandStatus = true;
    }

    public void collapse() {
        if (this.expandStatus) {
            this.mainApiData.setTreeStatus(Constants.TREE_STATUS_COLLAPSE);
            int selfIndex = this.parent.getApiTable().getTableData().indexOf(this.mainApiData);

            // 计算即将删除的行区间
            int startDeleteIndex = selfIndex + 1;
            int endDeleteIndex = selfIndex + subApiData.size();

            // 从后向前删除子项，这样索引就不会因为列表的变动而改变
            for (int i = subApiData.size() - 1; i >= 0; i--) {
                this.parent.getApiTable().getTableData().remove(startDeleteIndex);
            }

            // 现在所有的子项都被删除了，通知表格模型更新
            // 注意这里的索引是根据删除前的状态传递的
            this.parent.fireTableRowsDeleted(startDeleteIndex, endDeleteIndex - 1);

            this.expandStatus = false;
        }
    }

}
