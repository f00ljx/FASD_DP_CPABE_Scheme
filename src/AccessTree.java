import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

import static java.lang.Integer.valueOf;

public class AccessTree {

    //d-1次多项式表示为q(x)=coef[0] + coef[1]*x^1 + coef[2]*x^2 + coef[d-1]*x^(d-1)
    //多项式的系数的数据类型为Zr Element，从而是的后续相关计算全部在Zr群上进行
    //通过随机选取coef参数，来构造d-1次多项式q(x)。约束条件为q(0)=s。
    public static Element[] randomP(int d, Element s, Pairing bp) {
        Element[] coef = new Element[d];
        coef[0] = s;
        for (int i = 1; i < d; i++) {
            coef[i] = bp.getZr().newRandomElement().getImmutable();
        }
        return coef;
    }

    //计算由coef为系数确定的多项式qx在点index处的值，注意多项式计算在群Zr上进行
    public static Element qx(Element index, Element[] coef, Pairing bp) {
        Element res = coef[0].getImmutable();
        for (int i = 1; i < coef.length; i++) {
            Element exp = bp.getZr().newElement(i).getImmutable();
            //index一定要使用duplicate复制使用，因为index在每一次循环中都要使用，如果不加duplicte，index的值会发生变化
            res = res.add(coef[i].mul(index.duplicate().powZn(exp)));
        }
        return res;
    }

    //拉格朗日因子计算 i是集合S中的某个元素，x是目标点的值
    public static Element lagrange(int i, int[] S, int x,ArrayList<Node> nodes, Pairing bp) {
        Element res = bp.getZr().newOneElement().getImmutable();
        Element iElement = bp.getZr().newElement(i).getImmutable();
        Element xElement = bp.getZr().newElement(x).getImmutable();
        for (int j : S) {
            if (i != nodes.get(j).xindex) {
                //注意：在循环中重复使用的项一定要用duplicate复制出来使用
                //这儿xElement和iElement重复使用，但因为前面已经getImmutable所以可以不用duplicate
                Element numerator = xElement.sub(bp.getZr().newElement(nodes.get(j).xindex));
                Element denominator = iElement.sub(bp.getZr().newElement(nodes.get(j).xindex));
                res = res.mul(numerator.div(denominator));
            }
        }
        return res;
    }

    //没用递归的秘密共享过程
//    public static void rootShare(Node[] nodes, Element secret, Pairing bp){
//        nodes[0].secretShare = bp.getZr().newElement(10);
//        for (Node node : nodes) {
//            if (!node.isLeaf()) {
//                Element[] coef = randomP(node.gate[1], node.secretShare, bp);
//                for (Element e:coef){
//                    System.out.println(e);
//                }
//                for (int i=0; i<node.children.length; i++ ){
//                    nodes[node.children[i]].secretShare = qx(bp.getZr().newElement(node.children[i]), coef, bp);
//                }
//            }
//        }
//    }

    // 共享秘密
    // nodes是整颗树的所有节点，n是要分享秘密的节点
    public static void nodeShare(ArrayList<Node> nodes, Node n, Pairing bp) {
        // 如果是叶子节点，则不需要再分享
        if (!n.isLeaf()) {
            // 如果不是叶子节点，则先生成一个随机多项式，多项式的常数项为当前节点的秘密值（这个值将被用于分享）
            // 多项式的次数，由节点的gate对应的threshold决定
            Element[] coef = randomP(n.gate[0], n.secretShare, bp);
            //记录当前节点选择的多项式系数，用于后续策略更新
            n.coef = coef;
            for (int j = 0; j < n.children.size(); j++) {
                Node childNode = nodes.get(n.children.get(j));
                // 对于每一个子节点，以子节点的索引为横坐标，计算子节点的多项式值（也就是其对应的秘密分片）
                childNode.secretShare = qx(bp.getZr().newElement(n.x.get(j)), coef, bp);
                // 递归，将该子节点的秘密继续共享下去
                nodeShare(nodes, childNode, bp);
            }
        }
    }

    // 恢复秘密
    public static boolean nodeRecover(ArrayList<Node> nodes, Node n, Map<Integer, String> atts, Element g, Element K2, Element K3, String skdFileName, String ctFileName, Pairing bp) throws NoSuchAlgorithmException {
        if (!n.isLeaf()) {
            // 对于内部节点，维护一个子节点索引列表，用于秘密恢复。
            List<Integer> validChildrenList = new ArrayList<Integer>();
            int[] validChildren;
            // 遍历每一个子节点
            for (int j = 0; j < n.children.size(); j++) {
                //别名，代表nodes里面的结点
                Node childNode = nodes.get(n.children.get(j));

                //新对象，复制出来，对新对象的操作不影响nodes
                // Node childnode = new Node(n.children.get(j));

                // 递归调用，恢复子节点的秘密值
                if (nodeRecover(nodes, childNode, atts, g, K2, K3, skdFileName, ctFileName, bp)) {
                    //
                    validChildrenList.add(valueOf(n.children.get(j)));
                    // 如果满足条件的子节点个数已经达到门限值，则跳出循环，不再计算剩余的节点
                    if (validChildrenList.size() == n.gate[0]) {
                        n.valid = true;
                        break;
                    }
                }
            }
            // 如果可恢复的子节点个数等于门限值，则利用子节点的秘密分片恢复当前节点的秘密。
            if (validChildrenList.size() == n.gate[0]) {
                validChildren = validChildrenList.stream().mapToInt(i -> i).toArray();
                // 利用拉格朗日差值恢复秘密
                Element secret = bp.getGT().newZeroElement().getImmutable();
                for (int i : validChildren) {
                    Element delta = lagrange(nodes.get(i).xindex, validChildren, 0, nodes,bp);  //计算拉个朗日插值因子
                    secret = secret.mul(nodes.get(i).secretShare.duplicate().powZn(delta)); //以双线性对整体作为秘密值，因此用powzn做指数运算，用mul做连乘恢复秘密值
                }
                n.secretShare = secret.getImmutable();
            }
        } else {

            //判断rootnode的属性是否在useratt中
            if (atts.containsKey(n.att)) {
                //判断useratt中的属性值是否与rootnode的属性值相同
                Element H = FD_MU_Scheme.ZrhashH2(Integer.toString(n.att), bp).getImmutable();
                //获取useratt中的属性值
                String userattvalue = atts.get(n.att);
                Element h_att = FD_MU_Scheme.ZrhashH2(Integer.toString(n.att) + userattvalue, bp).getImmutable();
                //计算g^h_att
                Element g_h_att = g.duplicate().powZn(h_att.mul(H)).negate().getImmutable();
//                Element g_h_att_nav = g_h_att.negate();
                //验证双线性映射e(rootnode.g_nv,g_h_att)=1，则返回n.valide=ture
                if (bp.pairing(n.g_nv, g).equals(bp.pairing(g_h_att,g))) {
                    Properties ctProp = FD_MU_Scheme.loadPropFromFile(ctFileName);
                    Properties skProp = FD_MU_Scheme.loadPropFromFile(skdFileName);
                    //从私钥中读取K
                    Element K_att = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("K_" + n.att+n.uid))).getImmutable();
                    //从密文中读取C1_att,C2_att,C3_att
                    Element C1_att = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C1_" + n.att+n.uid))).getImmutable();
                    Element C2_att = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C2_" + n.att+n.uid))).getImmutable();
                    Element C3_att = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C3_" + n.att))).getImmutable();
                    //进行双线性对运算E1=e(K3,C1_att) E2=e(K2,C2_att) E3=e(K_att,C3_att)
                    Element E1 = bp.pairing(K3, C1_att).getImmutable();
                    Element E2 = bp.pairing(K2, C2_att).getImmutable();
                    Element E3 = bp.pairing(K_att, C3_att).getImmutable();
                    //E=E1*E2*E3
                    Element E = E1.mul(E2).mul(E3).getImmutable();
                    //get h,r,a from the Map<String, Element> vartest
//                    Element h = FD_MU_Scheme.vartest.get("h");
//                    Element r = FD_MU_Scheme.vartest.get("r");
//                    Element a = FD_MU_Scheme.vartest.get("a");
//                    if(E.equals(bp.pairing(g,h).powZn(n.secretShare.duplicate().mul(a.mul(r))))){
//                        System.out.println("验证成功");
//                    }
                    //设置当前节点秘密值为E
                    n.secretShare = E.getImmutable();
                    n.valid = true;
                }
            }
        }
        return n.valid;
    }


    public static void main(String[] args) {

        Pairing bp = PairingFactory.getPairing("F:/Program Files/Java/jpbc-2.0.0/params/curves/a.properties");

//        Node[] nodes = new Node[7];
//        nodes[0] = new Node(new int[]{2, 3}, new int[]{1, 2, 3});
//        nodes[1] = new Node(1);
//        nodes[2] = new Node(new int[]{2, 3}, new int[]{4, 5, 6});
//        nodes[3] = new Node(5);
//        nodes[4] = new Node(2);
//        nodes[5] = new Node(3);
//        nodes[6] = new Node(4);
//
//        nodes[0].secretShare = bp.getZr().newElement(10);
//        nodeShare(nodes, nodes[0], bp);
//        for (Node node : nodes) {
//            System.out.println(node);
//            System.out.println(node.secretShare);
//        }
//        System.out.println("________________________________________________");
//        System.out.println("________________________________________________");
//
//        for (Node node : nodes) {
//            if (!node.isLeaf()) {
//                node.secretShare = null;
//            }
//            System.out.println(node);
//            System.out.println(node.secretShare);
//        }
//
//        int[] AttList = {1, 2, 3, 5};
//        boolean res = nodeRecover(nodes, nodes[0], AttList, bp);
//
//        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++");
//        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++");
//
//        for (Node node : nodes) {
//            System.out.println(node);
//            System.out.println(node.secretShare);
//        }
//        System.out.println(res);
    }
}