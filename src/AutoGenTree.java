import java.util.ArrayList;

public class AutoGenTree {
    //属性列表、满三叉树层数
    public static ArrayList<Node> tree(int[] att, int k, String uid) {
        //k不等于1，无意义
        int nodenum = (int) (Math.pow(3, k) - 1) / 2;
        int notleafnodenum = (int) (Math.pow(3, k - 1) - 1) / 2;
        //满三叉树叶子节点个数
        int leafnodenum = (int) Math.pow(3, k - 1);
        //int leafnodenum = att.length;
//        Node[] actree = new Node[nodenum];
        ArrayList<Node> actree = new ArrayList<Node>();
        int j = 0;
        for (int i = 0; i < nodenum; i++) {

            if (i < notleafnodenum) {
                //统一阈值门（3,2）
                ArrayList<Integer> children = new ArrayList<Integer>();
                children.add(i * 3 + 1);
                children.add(i * 3 + 2);
                children.add(i * 3 + 3);
                actree.add(new Node(new int[]{2, 3}, children));
                actree.get(i).x=actree.get(i).children;

            }
            else {
                actree.add(new Node(att[j]));
                j++;
            }
            actree.get(i).index= i;
            actree.get(i).xindex=i;
            actree.get(i).uid = uid;

        }
        actree.get(0).root = true;
        //遍历整棵树，设置父节点指针
        for (int i = 0; i < nodenum; i++) {
            if (actree.get(i).children != null) {
                for (int child : actree.get(i).children) {
                    actree.get(child).parent = i;
                }
            }
        }
        return actree;
    }

    //    public static Node[] tree(String[] att){
//
//    }
    public static void main(String[] args) {
        int[] userAttList = {1, 2, 3, 4, 5, 6, 7, 8, 9};
        ArrayList<Node> actree = tree(userAttList, 3, "user1");
        System.out.println(actree);
    }
}
