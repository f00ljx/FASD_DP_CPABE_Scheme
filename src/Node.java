import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;

//@JsonIgnoreProperties({"g_nv", "coef", "secretShare"})
public class Node implements Serializable{
    // gate用两个数(t,n)表示，n表示子节点个数, t表示门限值
    // 如果是叶子节点，则为null
    public int[] gate;
    // children表示内部节点，此字段为子节点索引列表
    // 如果是叶子节点，则为null
    public ArrayList<Integer> children;
    //节点横坐标
    public int xindex;
    //子节点横坐标索引列表，初始为子节点索引列表，叶节点时为null,下标位置和children对应
    public ArrayList<Integer> x;
    //根节点标记
    public boolean root;
    //父节点指针
    //如果为根节点，则为null
    public int parent;
    // att表示属性值，
    // 如果是内部节点，此字段null
    public int att;

    public boolean leaf;

    //键值一致性校验
    public Element g_nv;
    //节点索引
    public int index;

    //对应多项式
    public Element[] coef;
    // 对应的秘密值
    public Element secretShare;

    //对应用户ID
    public String uid;
    //dup合并访问树时，标记较长的访问树
    public String flag;


    // 用于秘密恢复，表示此节点是否可以恢复
    public boolean valid;
    //无参数构造方法
    public Node() {
    }

    //内部节点的构造方法
    public Node(int[] gate,  ArrayList<Integer> children) {
        this.gate = gate;
        this.children = children;
    }

    //内部节点的set方法
    public void setGate(int[] gate) {
        this.gate = gate;
    }

    public void setChildren(ArrayList<Integer> children) {
        this.children = children;
    }

    // 叶子节点的构造方法
    public Node(int att) {
        this.att = att;
    }

    //Node对象的构造方法
    public Node(Node n) {
        this.gate = n.gate;
        this.children = n.children;
        this.xindex = n.xindex;
        this.x = n.x;
        this.root = n.root;
        this.parent = n.parent;
        this.att = n.att;
        this.leaf = n.leaf;
        this.g_nv = n.g_nv;
        this.index = n.index;
        this.coef = n.coef;
        this.secretShare = n.secretShare;
        this.uid = n.uid;
        this.valid = n.valid;
        this.flag = n.flag;
    }

    public boolean isLeaf() {
        return this.children == null ? true : false;
    }

    @Override
    public String toString() {
        if (this.isLeaf()) {
            return Integer.toString(this.att);
        } else {
            return Arrays.toString(this.gate);
        }
    }
//    private void writeObject(ObjectOutputStream out) throws IOException {
//        out.defaultWriteObject();
//        out.writeObject(g_nv.toBytes());
//        out.writeObject(coef.length);
//        for (Element e : coef) {
//            out.writeObject(e.toBytes());
//        }
//        out.writeObject(secretShare.toBytes());
//    }
//
//    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
//        in.defaultReadObject();
//        byte[] nvData = (byte[]) in.readObject();
//        g_nv = PairingFactory.getPairing("F:/Program Files/Java/jpbc-2.0.0/params/curves/a.properties").getG1().newElementFromBytes(nvData);
//        int coefLength = (int) in.readObject();
//        coef = new Element[coefLength];
//        for (int i = 0; i < coefLength; i++) {
//            byte[] coefData = (byte[]) in.readObject();
//            coef[i] = PairingFactory.getPairing("F:/Program Files/Java/jpbc-2.0.0/params/curves/a.properties").getZr().newElementFromBytes(coefData);
//        }
//        byte[] secretShareData = (byte[]) in.readObject();
//        secretShare = PairingFactory.getPairing("F:/Program Files/Java/jpbc-2.0.0/params/curves/a.properties").getG1().newElementFromBytes(secretShareData);
//    }


}