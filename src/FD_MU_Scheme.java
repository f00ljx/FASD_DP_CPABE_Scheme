import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECKey;
import java.util.*;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;


public class FD_MU_Scheme {
    //define a global Element k
    public static Element k;
    //define a global ArrayList<Node> accessTree

    public static ArrayList<Node> accessTree = new ArrayList<Node>();
    public static ArrayList<Node> encaccessTree = new ArrayList<Node>();
    public static ArrayList<Node> accessTree2 = new ArrayList<Node>();
    //define a global Map<String, Element> vartest
    public static Map<String, Element> vartest = new HashMap<String, Element>();
    //    public static Element encsecret;
//    public static Element tt;
//    public static Element tu;
//    public static Element ts;
//    public static Element tkci;
//    public static Element ty2;
//    public static Element talpha1;
//    public static Element tH2sum;
//    public static Element tegg;
//    public static Element tg;
    public static Element Sd;
    //定义一个全局队列
    public static Queue<Node> uidq = new LinkedList<Node>();


    public static void setup(Pairing bp, String PPFileName, String mskFileName) {
        // 一、基于特定椭圆曲线类型生成Pairing实例
        // 1.从文件导入椭圆曲线参数
//        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        // 二、生成公钥PP和主密钥MSK,选择素数域Zr上的随机元素alpha和a，选择群G上的生成元g、h、u
        // 1.选择群G1上的生成元g作为公钥
        Element g = bp.getG1().newRandomElement().getImmutable();
        // 2.选择群G1上的生成元h作为公钥
        Element h = bp.getG1().newRandomElement().getImmutable();
        // 3.选择群G1上的生成元u作为公钥
        Element u = bp.getG1().newRandomElement().getImmutable();
        // 4.选择群Zr上的随机元素alpha作为主密钥
        Element alpha = bp.getZr().newRandomElement().getImmutable();
        // 5.选择群Zr上的随机元素a作为主密钥
        Element a = bp.getZr().newRandomElement().getImmutable();
        //6.选择双线性映射e(g,g)^alpha作为公钥
        Element egg1_alpha = bp.pairing(g, g).powZn(alpha).getImmutable();
        //7.选择g^a作为公钥
        Element ga = g.powZn(a).getImmutable();

        //put all the attributes into the global Map<String, Element> vartest
        vartest.put("g", g);
        vartest.put("h", h);
        vartest.put("u", u);
        vartest.put("egg1_alpha", egg1_alpha);
        vartest.put("ga", ga);
        vartest.put("alpha", alpha);
        vartest.put("a", a);


        // 三、写入主密钥MSK和公钥PP
        // 1.写入主密钥MSK
        Properties mskProp = new Properties();
        mskProp.setProperty("alpha", Base64.getEncoder().withoutPadding().encodeToString(alpha.toBytes()));
        mskProp.setProperty("a", Base64.getEncoder().withoutPadding().encodeToString(a.toBytes()));
        //2.写入公钥PP
        Properties ppProp = new Properties();
        ppProp.setProperty("g", Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));
        ppProp.setProperty("h", Base64.getEncoder().withoutPadding().encodeToString(h.toBytes()));
        ppProp.setProperty("u", Base64.getEncoder().withoutPadding().encodeToString(u.toBytes()));
        ppProp.setProperty("egg1_alpha", Base64.getEncoder().withoutPadding().encodeToString(egg1_alpha.toBytes()));
        ppProp.setProperty("ga", Base64.getEncoder().withoutPadding().encodeToString(ga.toBytes()));

        //保存主密钥MSK和公钥PP
        storePropToFile(mskProp, mskFileName);
        storePropToFile(ppProp, PPFileName);

//     System.out.println("MSK = " + mskProp);
//     System.out.println("PP = " + ppProp);

    }

    //密钥生成方法KeyGEN，输入主私钥和用户属性键值对集合，生成解密密钥
    public static void KeyGen(Pairing bp, String PPFileName, String mskFileName, Map<Integer, String> useratt, String uid, String skFileName) throws Exception {
        // 一、从文件导入主密钥MSK和公钥PP
        // 1.从文件导入主密钥MSK
        Properties mskProp = loadPropFromFile(mskFileName);
        // 1.1.从文件导入椭圆曲线参数
//        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        //read alpha from mskProp
        String alphaStr = mskProp.getProperty("alpha");
        Element alpha = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(alphaStr)).getImmutable();
//read a from mskProp
        Element a = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("a"))).getImmutable();


        // 2.从文件导入公钥PP
        Properties ppProp = loadPropFromFile(PPFileName);
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("g"))).getImmutable();
        Element h = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("h"))).getImmutable();
        Element u = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("u"))).getImmutable();
//        Element egg1_alpha = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("egg1_alpha")));
//        Element ga = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("ga")));

        // 二、生成用户私钥SK
        // 1.选择群Zr上的随机元素r
        Element r = bp.getZr().newRandomElement().getImmutable();
        vartest.put("r", r);

        //计算K1=g^(alpha/a)*h^r,K2=g^r,K3=g^(a*r)
        Element K1 = g.powZn(alpha.div(a)).mul(h.powZn(r)).getImmutable();
        Element K2 = g.powZn(r).getImmutable();
        Element K3 = g.powZn(a.mul(r)).getImmutable();
        //对useratt中对每个键att的值value通过ZrhashH2计算其哈希值h_att，然后计算K_att=g^(h_att*r)*u^(-ar)
        Map<Integer, Element> K_att = new HashMap<>();
        for (Map.Entry<Integer, String> entry : useratt.entrySet()) {
            int att = entry.getKey();
            String value = entry.getValue();
            Element h_att = ZrhashH2(att + value, bp);
            Element K_att_i = g.powZn(h_att.mul(r)).mul(u.powZn(a.mul(r).negate())).getImmutable();
            K_att.put(att, K_att_i);
        }


        // 三、写入用户私钥sk
        // 1.写入用户私钥K1，K2，K3，K_att
        Properties skProp = new Properties();
        skProp.setProperty("K1", Base64.getEncoder().withoutPadding().encodeToString(K1.toBytes()));
        skProp.setProperty("K2", Base64.getEncoder().withoutPadding().encodeToString(K2.toBytes()));
        skProp.setProperty("K3", Base64.getEncoder().withoutPadding().encodeToString(K3.toBytes()));
        for (Map.Entry<Integer, Element> entry : K_att.entrySet()) {
            int att = entry.getKey();
            Element K_att_i = entry.getValue();
            String test = "K_" + att + uid;
            skProp.setProperty("K_" + att + uid, Base64.getEncoder().withoutPadding().encodeToString(K_att_i.toBytes()));
        }
        // 2.保存用户私钥SK
        storePropToFile(skProp, skFileName);

    }

    //加密方法ENC，输入公钥PP，访问树，明文M，生成密文C
    public static void Enc(Pairing bp, String PPFileName, Element message, Map<Integer, String> useratt, String uid, String ctFileName) throws Exception {
        // 一、从文件导入公钥PP
        // 1.从文件导入公钥PP
        Properties ppProp = loadPropFromFile(PPFileName);
        // 1.1.从文件导入椭圆曲线参数
//        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("g"))).getImmutable();
        Element h = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("h"))).getImmutable();
        Element u = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("u"))).getImmutable();
        Element egg1_alpha = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("egg1_alpha"))).getImmutable();
        Element ga = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("ga"))).getImmutable();


        // 二、生成密文C
        //存储密文组件
        Properties ctProp = new Properties();
        // 1.对消息message做哈希映射到群Zr上，作为秘密值s
        Element s = GhashH3(message, bp).getImmutable();
        //计算消息message的MD5
        MessageDigest mdck = MessageDigest.getInstance("MD5");
        mdck.update(message.toBytes());// 计算md5函数
        String hashedM = new BigInteger(1, mdck.digest()).toString(16);// 16是表示转换为16进制数
        //输出MD5
//        System.out.println("message-MD5:" + hashedM);
        //写入hashedM
        ctProp.setProperty("hashedM", hashedM);
        //随机选择Zr上的元素k
        k = bp.getZr().newRandomElement().getImmutable();
        vartest.put("k", k);
        //计算身份验证参数ga^(1/k)
        Element ga_1k = g.powZn(k).getImmutable();
        //写入ga_1k
        ctProp.setProperty("ga_1k_" + uid, Base64.getEncoder().withoutPadding().encodeToString(ga_1k.toBytes()));


        //先设置根节点要共享的秘密值
        encaccessTree.get(0).secretShare = s.getImmutable();
        //进行共享，使得每个叶子节点获得响应的秘密分片
        AccessTree.nodeShare(encaccessTree, encaccessTree.get(0), bp);

        //计算密文C=message*egg1_alpha^s
        Element C = message.mul(egg1_alpha.powZn(s)).getImmutable();
        //output the ciphertext C
//        System.out.println("Ciphertext C:" + C);
        //写入C
        ctProp.setProperty("C", Base64.getEncoder().withoutPadding().encodeToString(C.toBytes()));
        //计算密文组件C0=ga^s
        Element C0 = ga.powZn(s).getImmutable();
        //写入C0
        ctProp.setProperty("C0", Base64.getEncoder().withoutPadding().encodeToString(C0.toBytes()));
        //计算密文组件C1_att,C2_att,C3_att
        for (Node node : encaccessTree) {
            if (node.isLeaf()) {
                // 1.计算C1=g^(h_att*s)*u^(-as)
                Element CC1 = h.powZn(node.secretShare).getImmutable();
                Element H = ZrhashH2(Integer.toString(node.att), bp).getImmutable();
                Element C1 = CC1.mul(u.powZn(H)).getImmutable();
                //2.以当前叶节点att作为useratt的键，获取att对应值，并计算其哈希值h_att
                String value = useratt.get(node.att);
                Element h_att = ZrhashH2(Integer.toString(node.att) + value, bp).getImmutable();
                //3.计算C2_att=g^(-h_att*H)
                Element C2 = g.powZn(h_att.mul(H)).negate().getImmutable();
                node.g_nv = C2.getImmutable();
                //4.计算C3_att=g^(H)
                Element C3 = g.powZn(H).getImmutable();

                //写入C1_att,C2_att,C3_att
                ctProp.setProperty("C1_" + node.att + uid, Base64.getEncoder().withoutPadding().encodeToString(C1.toBytes()));
                ctProp.setProperty("C2_" + node.att + uid, Base64.getEncoder().withoutPadding().encodeToString(C2.toBytes()));
                ctProp.setProperty("C3_" + node.att, Base64.getEncoder().withoutPadding().encodeToString(C3.toBytes()));

            }
        }
        // 3.对访问策略中每个节点进行序列化，然后根据访问树中的节点顺序，将其写入密文Ct中
        //写入访问树长度
        // ctProp.setProperty("accessTreeLength", Integer.toString(accessTree.size()));
        // for (int i = 0; i < accessTree.size(); i++) {
        //    Node node = accessTree.get(i);

        //jason serialize the node

//            // 3.1.对节点进行jason序列化
//            ObjectMapper objectMapper = new ObjectMapper();
//            objectMapper.addMixInAnnotations(Node.class, NodeMixIn.class);
//            String nodejson = objectMapper.writeValueAsString(node);
//
        //写入节点
        //     ctProp.setProperty("node" + i, Base64.getEncoder().withoutPadding().encodeToString(nodejson.getBytes()));
//             3.1.对节点进行序列化
//            ByteArrayOutputStream baos = new ByteArrayOutputStream();
//            ObjectOutputStream oos = new ObjectOutputStream(baos);
//            oos.writeObject(node);
//            oos.flush();
//            oos.close();
//            //写入节点
//            ctProp.setProperty("node" + i, Base64.getEncoder().withoutPadding().encodeToString(baos.toByteArray()));
//            String nodeStr = SerializationUtils.serialize(node);
////             3.2.将序列化后的节点写入密文Ct
//            ctProp.setProperty("node" + i, nodeStr);


        // }

        //4.保存密文Ct
        storePropToFile(ctProp, ctFileName);


    }

    //构建dup方法，输入密文ct，userid，访问树2
    public static void Dup(Pairing bp, String ctFileName, String ctFileName2, String uid) throws Exception {
        // 一、从文件导入密文Ct
        // 1.从文件导入密文Ct
        Properties ctProp = loadPropFromFile(ctFileName);
        Properties ctProp2 = loadPropFromFile(ctFileName2);
        // 1.1.从文件导入椭圆曲线参数
//        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        //1.2.从文件导入hashedM用于判重
        String hashedM = ctProp.getProperty("hashedM");
        String hashedM1 = ctProp2.getProperty("hashedM");
        //判断是否重复密文，如果不是重复密文则退出
        if (!hashedM.equals(hashedM1)) {
            System.out.println("不是重复密文，退出");
            return;
        }
        Element ga_1k = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp2.getProperty("ga_1k_" + uid)));
        ctProp.setProperty("ga_1k_" + uid, Base64.getEncoder().withoutPadding().encodeToString(ga_1k.toBytes()));

        // 1.3.从文件读取访问树长度，并以此导入访问树
        //原始访问树
        int accessTreeLength1 = accessTree.size();
        ArrayList<Node> accessTree1 = new ArrayList<>();
        for (Node node : accessTree) {
            accessTree1.add(new Node(node));
        }
//        for (int i = 0; i < accessTreeLength; i++) {
//            // 1.3.1.从文件读取节点
//            byte[] bytes = Base64.getDecoder().decode(ctProp.getProperty("node" + i));
//            String nodejson = new String(bytes);
//            ObjectMapper objectMapper = new ObjectMapper();
//            Node node = objectMapper.readValue(nodejson, Node.class);
//            // 1.3.2.将节点存入访问树
//            accessTree1.add(node);
//        }
        //新访问树
        int accessTreeLength2 = accessTree2.size();
//        ArrayList<Node> accessTree2 = new ArrayList<Node>();
//        for (int i = 0; i < accessTreeLength; i++) {
//            // 1.3.1.从文件读取节点
//            byte[] bytes = Base64.getDecoder().decode(ctProp2.getProperty("node" + i));
//            ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
//            ObjectInputStream ois = new ObjectInputStream(bais);
//            Node node = (Node) ois.readObject();
//            // 1.3.2.将节点存入访问树
//            accessTree2.add(node);
//        }

        //读取ctFileName中所有C3_att
        Map<String, Element> C3_att1 = new HashMap<>();
        for (Node node : accessTree1) {
            if (node.isLeaf()) {
                // 1.3.1.从文件读取C3_att
                byte[] bytes = Base64.getDecoder().decode(ctProp.getProperty("C3_" + node.att));
                Element C3 = bp.getG1().newElementFromBytes(bytes).getImmutable();
                C3_att1.put(Integer.toString(node.att), C3);
            }
        }

        //读取ctFileName2中所有C1_att.C2_att.C3_att
        for (Node node : accessTree2) {
            if (node.isLeaf()) {
                // 1.3.1.从文件读取C1_att
                byte[] bytes = Base64.getDecoder().decode(ctProp2.getProperty("C1_" + node.att + uid));
                Element C1 = bp.getG1().newElementFromBytes(bytes).getImmutable();
                //C1写入ctFileName
                ctProp.setProperty("C1_" + node.att + uid, Base64.getEncoder().withoutPadding().encodeToString(C1.toBytes()));
                // 1.3.1.从文件读取C2_att
                bytes = Base64.getDecoder().decode(ctProp2.getProperty("C2_" + node.att + uid));
                Element C2 = bp.getG1().newElementFromBytes(bytes).getImmutable();
                //C2写入ctFileName
                ctProp.setProperty("C2_" + node.att + uid, Base64.getEncoder().withoutPadding().encodeToString(C2.toBytes()));
                // 1.3.1.从文件读取C3_att
                bytes = Base64.getDecoder().decode(ctProp2.getProperty("C3_" + node.att));
                Element C3 = bp.getG1().newElementFromBytes(bytes).getImmutable();
                //检查是C3是否已经存在于C3_att1中，如果不在则写入ctFileName ，如果在则continue
                if (!C3_att1.containsKey(Integer.toString(node.att))) {
                    ctProp.setProperty("C3_" + node.att, Base64.getEncoder().withoutPadding().encodeToString(C3.toBytes()));
                }
            }
        }

        //合并访问树1和2，产生一颗新的访问树
        //定义节点总数nodenum为访问树1和2的长度之和加1
        int nodenum = accessTree1.size() + accessTree2.size() + 1;
        //创建一个新的访问树，节点个数为定义节点总数nodenum为访问树1和2的长度之和加1
        ArrayList<Node> accessTreenew = new ArrayList<Node>();
        ;
        //创建一个gate为(1,2)的新节点作为根节点
        ArrayList<Integer> children = new ArrayList<Integer>();
        children.add(1);
        children.add(2);
        accessTreenew.add(new Node(new int[]{1, 2}, children));
        accessTreenew.get(0).index = 0;
        accessTreenew.get(0).secretShare = accessTree1.get(0).secretShare;
        //比较访问树1和2的长度，选择较长的长度作为accessTree1
        if (accessTree1.size() < accessTree2.size()) {
            ArrayList<Node> temp = new ArrayList<>();
            for (Node node : accessTree1)
                temp.add(new Node(node));
            accessTree1 = new ArrayList<Node>();
            ;
            for (Node node : accessTree2)
                accessTree1.add(new Node(node));
            accessTree2 = new ArrayList<Node>();
            ;
            for (Node node : temp)
                accessTree2.add(new Node(node));
        }
        //遍历访问树1，将flag置为accessTree1
        for (Node node : accessTree1) {
            node.flag = "accessTree1";
        }
        //遍历访问树2，将flag置为accessTree2
        for (Node node : accessTree2) {
            node.flag = "accessTree2";
        }

        //将访问树1和2的根节点分别作为新访问树的第一个和第二个节点
        accessTreenew.add(new Node(accessTree1.get(0)));
        accessTreenew.add(new Node(accessTree2.get(0)));
        //设置访问树1和2的根节点的父节点指针为新访问树的根节点
        accessTreenew.get(1).parent = 0;
        accessTreenew.get(2).parent = 0;
        //定义标志f，初始表示访问树2的根节点uid。默认多次合并后，较短的访问树2根节点uid存在
        String f2 = accessTree2.get(0).flag;
        //定义变量tail，表示当前访问树已更新编号的最后一个节点索引
        int tail = 2;
        //清空队列uidq
        uidq = new LinkedList<Node>();
        //根据节点总数进行循环创建新访问树，根节点已经创建，从1开始循环
        for (int i = 1; i < nodenum; i++) {
            //如果当前节点不为叶子节点
            if (accessTreenew.get(i).children != null) {
                String f = accessTreenew.get(i).flag;
                //创建当前节点子节点长度大小的整型数组
                ArrayList<Integer> childindex = new ArrayList<Integer>();
                for (int j = 0; j < accessTreenew.get(i).children.size(); j++) {
                    //tail加1
                    tail++;
                    //新建节点对象表示当前节点的子节点
//                    if(f.equals(f1)){
//                        Node childnode = accessTree2[accessTree.get(i).children[j]];
//                        int index = childnode.index;
//                    }
//                    else {
//                        Node childnode = accessTree1[accessTree.get(i).children[j]];
//                        int index = childnode.index;
//                    }
                    //获取当前节点孩子节点的索引值
                    int index = accessTreenew.get(i).children.get(j);
                    //判断属于f和f2是否相等
                    if (f.equals(f2)) {
                        accessTreenew.add(new Node(accessTree2.get(index)));
                        accessTreenew.get(accessTreenew.size() - 1).parent = i;
                    } else {
                        accessTreenew.add(new Node(accessTree1.get(index)));
                        accessTreenew.get(accessTreenew.size() - 1).parent = i;

                    }
                    //添加tail到childindex数组中
                    childindex.add(tail);
                }
                //更新当前节点的索引
                accessTreenew.get(i).index = i;
                //判断当前节点的root标记，如果为true，则将当前节点加入uidq队列
                if (accessTreenew.get(i).root) {
                    uidq.add(new Node(accessTreenew.get(i)));
                }
                //更新当前节点的子节点索引
                accessTreenew.get(i).setChildren(childindex);
            } else {
                accessTreenew.get(i).index = i;
            }

        }
        accessTree = new ArrayList<Node>();
        for (Node node : accessTreenew)
            accessTree.add(new Node(node));
        //写入新访问树的长度
//        ctProp.setProperty("accessTreeLength", Integer.toString(accessTreenew.size()));
//        for (int i = 0; i < accessTreenew.size(); i++) {
//            Node node = accessTreenew.get(i);
//            // 3.1.对节点进行序列化
//            // 3.1.对节点进行jason序列化
//            ObjectMapper objectMapper = new ObjectMapper();
//            String nodejson = objectMapper.writeValueAsString(node);
////            ByteArrayOutputStream baos = new ByteArrayOutputStream();
////            ObjectOutputStream oos = new ObjectOutputStream(baos);
////            oos.writeObject(node);
////            oos.flush();
////            oos.close();
//            // 3.2.将序列化后的节点写入密文Ct
//            ctProp.setProperty("node" + i,Base64.getEncoder().withoutPadding().encodeToString(nodejson.getBytes()));
//        }

        //保存ctProp
        storePropToFile(ctProp, ctFileName);
    }


    //更新密钥生成算法UKeyGen，输入公共参数PP，uid，更新类型UType，当前叶节点Y，新叶节点Ynew，访问树T，输出更新密钥UK
    public static void UKeyGen(Pairing bp, String PPFileName, String ctFileName, String uid, int UType, Node Y, Node Ynew, String Ynewvalue, String ukFileName) throws IOException, NoSuchAlgorithmException, ClassNotFoundException {
        //获得参数曲线bp
//        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        //从PPFileName导入读取公共参数PP
        long start = System.currentTimeMillis();
        long end;
        Properties ppProp = loadPropFromFile(PPFileName);
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("g"))).getImmutable();
        Element h = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("h"))).getImmutable();
        Element u = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("u"))).getImmutable();

        //从ctFileName中读取Y.att对应的C2_att
        Properties ctProp = loadPropFromFile(ctFileName);
        Element C2_att = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C2_" + Y.att + uid))).getImmutable();


        //计算gk=g^k
        Element gk = u.duplicate().powZn(k).getImmutable();
        //写入ukFileName,gk
        Properties ukProp = new Properties();
        ukProp.setProperty("gk_" + uid, Base64.getEncoder().encodeToString(gk.toBytes()));
        //写入节点Y和Ynew的属性值
        ukProp.setProperty("Y_att_" + uid, Integer.toString(Y.att));
        //如果Ynew为null。写入空字符串
//        if (Ynew == null) {
//            ukProp.setProperty("Ynew_att_" + uid, "");
//        }
        //否则写入Ynew的属性值
//        else {
//            ukProp.setProperty("Ynew_att_" + uid, Integer.toString(Ynew.att));
//        }
        //写入Ynew的属性值
        //ukProp.setProperty("Ynew_att_" + uid, Integer.toString(Ynew.att));

        //对属性Y和Ynew进行哈希ZrhashH2
        Element Yhash = ZrhashH2(Integer.toString(Y.att), bp).getImmutable();

        Element Ynewhash = ZrhashH2(Integer.toString(Ynew.att), bp).getImmutable();
        Element Ynewvaluehash = ZrhashH2(Integer.toString(Y.att) + Ynewvalue, bp).getImmutable();

        int accessTreeLength = accessTree2.size();
        //读取访问树
//        int accessTreeLength = Integer.parseInt(ctProp.getProperty("accessTreeLength"));
//        ArrayList<Node> accessTree = new ArrayList<Node>();
//        for (int i = 0; i < accessTreeLength; i++) {
//            //从文件读取节点
//            byte[] bytes = Base64.getDecoder().decode(ctProp.getProperty("node" + i));
//            String nodejson = new String(bytes);
//            ObjectMapper objectMapper = new ObjectMapper();
//            Node node = objectMapper.readValue(nodejson, Node.class);
//            //将节点存入访问树
//            accessTree.add(node);
//        }

        //swich-case判断更新类型UType
        switch (UType) {
            //如果更新类型为1，表示更新叶节点
            case 1:
                //计算更新密钥UK1=u^(Ynewhash-Yhash)
                Element UK1 = u.duplicate().powZn(Ynewhash.duplicate().sub(Yhash));
                //计算C2_att的倒数
                Element C2_att_inverse = C2_att.duplicate().invert();
                //计算更新密钥UK2=C2_att_inverse^(-Ynewhash*Yhash)
                Element UK2 = C2_att_inverse.duplicate().powZn(Ynewhash.duplicate().mul(Ynewvaluehash).negate());
                //计算C3_att=g^Ynewhash
                Element C3_att = g.duplicate().powZn(Ynewhash);
                //写入更新密钥UK1,Uk2,C3_att
                ukProp.setProperty("UK1_" + Ynew.att + "_" + uid, Base64.getEncoder().encodeToString(UK1.toBytes()));
                ukProp.setProperty("UK2_" + Ynew.att + "_" + uid, Base64.getEncoder().encodeToString(UK2.toBytes()));
                ukProp.setProperty("C3_" + Ynew.att, Base64.getEncoder().encodeToString(C3_att.toBytes()));
                //写入UType
                ukProp.setProperty("UType_" + uid, Integer.toString(UType));
                end = System.currentTimeMillis();
                System.out.println("Type1 Time:" + (end - start)+"ms");
                break;

            case 2:
                //计算Ynew的秘密值分片
                int Ynewxindex = Ynew.xindex;
                //计算秘密值分片
                Ynew.secretShare = AccessTree.qx(bp.getZr().newElement(Ynewxindex), accessTree.get(Ynew.parent).coef, bp);
                //计算UK1=h^Ynew.secretShare*u^Ynewhash
                Element UK1_2 = h.duplicate().powZn(Ynew.secretShare).mul(u.duplicate().powZn(Ynewhash));
                //计算UK2=g^(-Ynewhash*Ynewvaluehash)
                Element UK2_2 = g.duplicate().powZn(Ynewhash.duplicate().mul(Ynewvaluehash).negate());
                //计算C3_att=g^Ynewhash
                Element C3_att_2 = g.duplicate().powZn(Ynewhash);
                //写入更新密钥UK1,Uk2,C3_att
                ukProp.setProperty("UK1_" + Ynew.att + "_" + uid, Base64.getEncoder().encodeToString(UK1_2.toBytes()));
                ukProp.setProperty("UK2_" + Ynew.att + "_" + uid, Base64.getEncoder().encodeToString(UK2_2.toBytes()));
                ukProp.setProperty("C3_" + Ynew.att, Base64.getEncoder().encodeToString(C3_att_2.toBytes()));
                //写入UType
                ukProp.setProperty("UType_" + uid, Integer.toString(UType));
                end = System.currentTimeMillis();
                System.out.println("Type2 Time:" + (end - start)+"ms");
                break;
            case 3:
                int t = accessTree.get(Y.parent).gate[0];
                int n = accessTree.get(Y.parent).gate[1];
                //删除访问树中的Y节点----------------------------------------------------------------------------------------------------------------------
                //第一种情况，如果t<n并且n>2
                if (t < n && n > 2) {
                    //定义type3=1
                    int type3 = 1;
                    //写入type3
                    ukProp.setProperty("type3_" + uid, Integer.toString(type3));
                    //写入UType
                    ukProp.setProperty("UType_" + uid, Integer.toString(UType));
                    end = System.currentTimeMillis();
                    System.out.println("Type3-i Time:" + (end - start)+"ms");
                    break;
                }
                //第二种情况t=n且n>2
                if  (t == n && n > 2) {
                    //定义type3=2
                    int type3 = 2;
                    //写入type3
                    ukProp.setProperty("type3_" + uid, Integer.toString(type3));
                    //写入UType
                    ukProp.setProperty("UType_" + uid, Integer.toString(UType));
                    //创建一个节点数组，包含节点Y的父节点和Y父节点的除了Y节点的所有子节点
                    ArrayList<Node> YparentAndChildren = new ArrayList<Node>();
                    //定义一个Node类型的队列travetse
                    Queue<Node> travetse = new LinkedList<Node>();
                    //将Y的父节点放入队列中
                    travetse.add(accessTree.get(Y.parent));
                    //do while循环
                    do {
                        Node nn = travetse.poll();
                        if (nn.index != Y.index)
                            YparentAndChildren.add(new Node(nn));
                        //如果该节点不为叶节点，将nn的所有子节点加入队列中
                        if (nn.children != null) {
                            for (int i = 0; i < nn.children.size(); i++) {
                                travetse.add(accessTree.get(nn.children.get(i)));
                            }
                        }

                    } while (!travetse.isEmpty());


                    //将Y父节点的除了Y节点的所有子节点放入节点数组中
//                    for (int i = 0; i < accessTree.get(Y.parent).children.size(); i++) {
//                        if (accessTree.get(Y.parent).children.get(i) == Y.index) {
//                            continue;
//                        }
//                        YparentAndChildren.add(accessTree.get(accessTree.get(Y.parent).children.get(i)));
////                        YparentAndChildren.set(position, accessTree.get(accessTree.get(Y.parent).children.get(i)));
////                        position++;
//                    }

                    //根节点阈值门设置更换
                    YparentAndChildren.get(0).gate[0]--;
                    YparentAndChildren.get(0).gate[1]--;
                    //重新分配秘密值
                    AccessTree.nodeShare(accessTree, YparentAndChildren.get(0), bp);
                    //遍历YparentAndChildren的child
                    for (int i = 1; i < YparentAndChildren.size(); i++) {
                        Node renode = YparentAndChildren.get(i);
                        if (renode.isLeaf()) {
                            //计算UK1_att=h^(YparentAndChildren.get(i)-Y.secretShare)
                            Element UK1_3 = h.powZn(renode.secretShare.duplicate().sub(accessTree.get(renode.index).secretShare));
                            //写入UK1
                            ukProp.setProperty("UK1_" + renode.att + "_" + uid, Base64.getEncoder().encodeToString(UK1_3.toBytes()));
                        }

                    }
                    end = System.currentTimeMillis();
                    System.out.println("Type3-ii Time:" + (end - start)+"ms");
                    //写入受影响节点长度
//                    ukProp.setProperty("YparentAndChildren", Integer.toString(YparentAndChildren.size()));
//                    for (int i = 0; i < YparentAndChildren.size(); i++) {
//                        Node node = YparentAndChildren.get(i);
//                        // 3.1.对节点进行序列化
//                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
//                        ObjectOutputStream oos = new ObjectOutputStream(baos);
//                        oos.writeObject(node);
//                        oos.flush();
//                        oos.close();
//                        // 3.2.将序列化后的节点写入密文Ct
//                        ukProp.setProperty("node" + i, Base64.getEncoder().withoutPadding().encodeToString(baos.toByteArray()));
//                    }
                    System.out.println("受影响节点个数："+YparentAndChildren.size());
                    accessTree2 = YparentAndChildren;
                    break;
                }
                //第三种情况n=2,t=1
                if (n == 2) {
                    //定义type3=3
                    int type3 = 3;
                    //写入type3
                    ukProp.setProperty("type3_" + uid, Integer.toString(type3));
                    Node Yparent = accessTree.get(Y.parent);
                    Element UK1_3 = h.powZn(Yparent.secretShare.duplicate().sub(Ynew.secretShare));
                    //写入UK1
                    ukProp.setProperty("UK1_" + Ynew.att + "_" + uid, Base64.getEncoder().encodeToString(UK1_3.toBytes()));
                    ukProp.setProperty("UType_" + uid, Integer.toString(UType));
                    end = System.currentTimeMillis();
                    System.out.println("Type3-iii Time:" + (end - start)+"ms");
                    break;
                }
                //第四种情况n=2,t=2
//                if (n == 2 && t == 2) {
//                    //定义type3=4
//                    int type3 = 4;
//                    //写入type3
//                    ukProp.setProperty("type3_" + uid, Integer.toString(type3));
//
//                    ArrayList<Node> YbroAndChildren = new ArrayList<Node>();
//                    //定义一个Node类型的队列travetse
//                    Queue<Node> travetse = new LinkedList<Node>();
//                    //将Y的兄弟节点放入队列中
//                    travetse.add(accessTree.get(Ynew.index));
//                    //do while循环
//                    do {
//                        Node nn = travetse.poll();
//                        YbroAndChildren.add(nn);
//                        //如果该节点不为叶节点，将nn的所有子节点加入队列中
//                        if (nn.children != null) {
//                            for (int i = 0; i < nn.children.size(); i++) {
//                                travetse.add(accessTree.get(nn.children.get(i)));
//                            }
//                        }
//
//                    } while (!travetse.isEmpty());
//                    //重新分配秘密值
//                    YbroAndChildren.get(0).secretShare = accessTree.get(Y.parent).secretShare;
//                    AccessTree.nodeShare(YbroAndChildren, YbroAndChildren.get(0), bp);
//                    //遍历YparentAndChildren的child
//                    for (int i = 1; i <= YbroAndChildren.size(); i++) {
//                        Node renode = YbroAndChildren.get(i);
//                        if (renode.isLeaf()) {
//                            //计算UK1_att=h^(YparentAndChildren.get(i)-Y.secretShare)
//                            Element UK1_3 = h.powZn(renode.secretShare.duplicate().sub(accessTree.get(renode.index).secretShare));
//                            //写入UK1
//                            ukProp.setProperty("UK1_" + renode.att + "_" + uid, Base64.getEncoder().encodeToString(UK1_3.toBytes()));
//                        }
//
//                    }
//                    accessTree2 = YbroAndChildren;
//                }
                //写入UType

            default:
                //输出更新类型错误
                System.out.println("Update type error!");
                break;

        }
        //保存更新密钥
        storePropToFile(ukProp, ukFileName);

    }

    //密文更新函数CTUpdate，输入参数为pairingParametersFileName，密文文件，更新密钥文件
    public static void CTUpdate(Pairing bp, String PPFileName, String ctFileName, Node Y, Node Ynew, String uid, String ukFileName) throws Exception {
        //设置bp
//        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        long start = System.currentTimeMillis();
        long end;
        //读取密文ct
        Properties ppProp = loadPropFromFile(PPFileName);
        // 1.1.从文件导入椭圆曲线参数
//        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element u = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("u"))).getImmutable();
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("g"))).getImmutable();

        Properties ctProp = loadPropFromFile(ctFileName);
        //读取身份验证参数ga_1k
        Element ga_1k = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("ga_1k_" + uid)));

        int accessTreeLength = accessTree.size();
//        //读取访问树
//        int accessTreeLength = Integer.parseInt(ctProp.getProperty("accessTreeLength"));
//        ArrayList<Node> accessTree = new ArrayList<Node>();
//        for (int i = 0; i < accessTreeLength; i++) {
//            //从文件读取节点
//            byte[] bytes = Base64.getDecoder().decode(ctProp.getProperty("node" + i));
//            String nodejson = new String(bytes);
//            ObjectMapper objectMapper = new ObjectMapper();
//            Node node = objectMapper.readValue(nodejson, Node.class);
//            //将节点存入访问树
//            accessTree.add(node);
//        }
        //读取ctFileName中所有C1_att.C2_att.C3_att
//        HashMap<String, Element> C1_att = new HashMap<>();
//        HashMap<String, Element> C2_att = new HashMap<>();
//        for (int i = 0; i < accessTreeLength; i++) {
//            Node node = accessTree.get(i);
//            if (node.isLeaf()) {
//                //从文件读取C1_att
//                byte[] bytes = Base64.getDecoder().decode(ctProp.getProperty("C1_" + node.att + uid));
//                Element C1 = bp.getG1().newElementFromBytes(bytes).getImmutable();
//                //将C1_att存入C1_att
//                C1_att.put(Integer.toString(node.att), C1);
//                //从文件读取C2_att
//                bytes = Base64.getDecoder().decode(ctProp.getProperty("C2_" + node.att + uid));
//                Element C2 = bp.getG1().newElementFromBytes(bytes).getImmutable();
//                //将C2_att存入C2_att
//                C2_att.put(Integer.toString(node.att), C2);
//            }
//        }

        //读取更新密钥
        Properties ukProp = loadPropFromFile(ukFileName);
        //读取gk
        byte[] bytes = Base64.getDecoder().decode(ukProp.getProperty("gk_" + uid));
        Element gk = bp.getG1().newElementFromBytes(bytes).getImmutable();
        //验证双线性映射e(ga_1k,gk)=1，否则return
        if (!bp.pairing(ga_1k, u).equals(bp.pairing(g, gk))) {
            System.out.println("Error data provider!");
            return;
        }
        //从文件导入UTYpe
        int UType = Integer.parseInt(ukProp.getProperty("UType_" + uid));
        //根据UType进行更新
        switch (UType) {
            case 1:
                //从ct中读取Y_att对应的C1_att,C2_att
                //从文件读取C1_att
                bytes = Base64.getDecoder().decode(ctProp.getProperty("C1_" + Y.att + uid));
                Element C1_att = bp.getG1().newElementFromBytes(bytes).getImmutable();
                //从文件读取C2_att
                bytes = Base64.getDecoder().decode(ctProp.getProperty("C2_" + Y.att + uid));
                Element C2_att = bp.getG1().newElementFromBytes(bytes).getImmutable();

                //从文件读取UK1_att，UK2_att
                bytes = Base64.getDecoder().decode(ukProp.getProperty("UK1_" + Ynew.att + "_" + uid));
                Element UK1_att = bp.getG1().newElementFromBytes(bytes).getImmutable();
                bytes = Base64.getDecoder().decode(ukProp.getProperty("UK2_" + Ynew.att + "_" + uid));
                Element UK2_att = bp.getG1().newElementFromBytes(bytes).getImmutable();
                //从更新密钥文件中读取C3_att
                bytes = Base64.getDecoder().decode(ukProp.getProperty("C3_" + Ynew.att));
                Element C3_att = bp.getG1().newElementFromBytes(bytes).getImmutable();

                //更新C1_att
                Element C1_att_Y = C1_att.duplicate().mul(UK1_att);
                //写入C1_att覆盖原文
                ctProp.remove("C1_" + Y.att + uid);
                ctProp.setProperty("C1_" + Ynew.att + uid, Base64.getEncoder().encodeToString(C1_att_Y.toBytes()));
                //更新C2_att
                Element C2_att_Y = C2_att.duplicate().mul(UK2_att);
                //写入C2_att覆盖原文
                ctProp.remove("C2_" + Y.att + uid);
                ctProp.setProperty("C2_" + Ynew.att + uid, Base64.getEncoder().encodeToString(C2_att_Y.toBytes()));
                //写入C3_att
                if (!ctProp.containsKey("C3_" + Ynew.att))
                    ctProp.setProperty("C3_" + Ynew.att, Base64.getEncoder().encodeToString(C3_att.toBytes()));
                //update accessTree from Y to Ynew
                accessTree.get(Y.index).att = Ynew.att;
                end  = System.currentTimeMillis();
                System.out.println("CTUpdate1 time: " + (end - start) + "ms");
                break;
            case 2:
                //type2为add，Y为新增节点Ynew的左兄弟节点
                //Y is the insert position node
                //从文件读取UK1_att，UK2_att
                bytes = Base64.getDecoder().decode(ukProp.getProperty("UK1_" + Ynew.att + "_" + uid));
                Element UK1_att_2 = bp.getG1().newElementFromBytes(bytes).getImmutable();
                bytes = Base64.getDecoder().decode(ukProp.getProperty("UK2_" + Ynew.att + "_" + uid));
                Element UK2_att_2 = bp.getG1().newElementFromBytes(bytes).getImmutable();
                //从更新密钥文件中读取C3_att
                bytes = Base64.getDecoder().decode(ukProp.getProperty("C3_" + Ynew.att));
                Element C3_att_2 = bp.getG1().newElementFromBytes(bytes).getImmutable();
                //更新C1_att
                Element C1_att_2 = UK1_att_2;
                //写入C1_att
                ctProp.setProperty("C1_" + Ynew.att + uid, Base64.getEncoder().encodeToString(C1_att_2.toBytes()));
                //更新C2_att
                Element C2_att_2 = UK2_att_2;
                //写入C2_att
                ctProp.setProperty("C2_" + Ynew.att + uid, Base64.getEncoder().encodeToString(C2_att_2.toBytes()));
                //写入C3_att
                ctProp.setProperty("C3_" + Ynew.att, Base64.getEncoder().encodeToString(C3_att_2.toBytes()));
                //将节点Ynew加入访问树,作为最后一个兄弟节点的位置
                int Yindex = Y.index;
                accessTree.add(Ynew.index, new Node(Ynew));
                int UaccessTreeLength = accessTree.size();
                //遍历Y父节点的子节点索引，获取Y.index的位置
//                int pos = 0;
//                boolean insertpos = false;
//                for (int i = 0; i < accessTree.get(Y.parent).children.size(); i++) {
//                    if (insertpos) {
//                        accessTree.get(Y.parent).children.set(i, accessTree.get(Y.parent).children.get(i) + 1);
//                        accessTree.get(accessTree.get(Y.parent).children.get(i)).index = accessTree.get(Y.parent).children.get(i);
//                    }
//                    if (!insertpos && accessTree.get(Y.parent).children.get(i) == Y.index) {
//                        pos = i + 1;
//                        insertpos = true;
//                    }
//                }


                //插入Ynew索引
                accessTree.get(Y.parent).children.add(Ynew.index);
                accessTree.get(Y.parent).x.add(Ynew.xindex);
                accessTree.get(Y.parent).gate[1]++;
                //get accessTree.get(Y.parent).children.size()
                int YparentchildLength = accessTree.get(Y.parent).children.size();
                //更新后续节点的索引
                for (int i = Ynew.index + 1; i < UaccessTreeLength; ) {
                    //获取Y父节点
                    Node Yparent = new Node(accessTree.get(accessTree.get(i).parent));
                    //获取Y父节点child长度
                    int parentchildLength = Yparent.children.size();
                    //遍历Y父节点的子节点
                    for (int j = 0; j < parentchildLength; j++) {
                        //update children index
                        accessTree.get(accessTree.get(i).parent).children.set(j, Yparent.children.get(j) + 1);
                        //update node index
                        accessTree.get(i + j).index = i + j;
                    }
                    //i步长为父节点的子节点个数
                    i += parentchildLength;
                }
                end  = System.currentTimeMillis();
                System.out.println("CTUpdate2 time: " + (end - start) + "ms");
                break;
            case 3:
                //从文件中读取type3
                int type3 = Integer.parseInt(ukProp.getProperty("type3_" + uid));
                //如果type3=1
                if (type3 == 1) {
                    //remove Y's C1_att and C2_att
                    ctProp.remove("C1_" + Y.att + uid);
                    ctProp.remove("C2_" + Y.att + uid);
                    //define Y's index
                    Yindex = Y.index;
                    //define Y's parentindex
                    int Yparentindex = accessTree.get(Y.parent).index;
                    //遍历Y父节点的子节点索引，获取Y.index的位置
                    int pos = 0;
                    boolean insertpos = false;
                    for (int i = 0; i < accessTree.get(Y.parent).children.size(); i++) {
                        if (insertpos) {
                            accessTree.get(accessTree.get(Yparentindex).children.get(i)).index--;
                            accessTree.get(Yparentindex).children.set(i, accessTree.get(Yparentindex).children.get(i) - 1);
//                            Yparent=accessTree.get(Yparentindex);

                        }
                        if (!insertpos && accessTree.get(Yparentindex).children.get(i) == Yindex) {
                            pos = i;
                            insertpos = true;
                        }
                    }

                    //remove Y.index from accessTree.get(Y.parent).children
                    accessTree.get(Yparentindex).children.remove(pos);
                    accessTree.get(Yparentindex).x.remove(pos);
                    //get accessTree.get(Y.parent).children.size()
                    YparentchildLength = accessTree.get(Yparentindex).children.size();
                    //let accessTree.get(Y.parent)'s gate be (t,n) to (t,n-1)
                    accessTree.get(Yparentindex).gate[1]--;
                    //remove Y from accessTree
                    accessTree.remove(Yindex);
                    UaccessTreeLength = accessTree.size();
                    //更新后续节点的索引
                    for (int i = accessTree.get(Yparentindex).children.get(YparentchildLength - 1) + 1; i < UaccessTreeLength; ) {
                        //获取Y父节点child长度
                        int parentchildLength = accessTree.get(accessTree.get(i).parent).children.size();
                        //遍历Y父节点的子节点
                        for (int j = 0; j < parentchildLength; j++) {
                            //update children index
                            accessTree.get(accessTree.get(i).parent).children.set(j, accessTree.get(accessTree.get(i).parent).children.get(j) - 1);
                            //update node index
                            accessTree.get(i + j).index = i + j;
                        }
                        //i步长为父节点的子节点个数
                        i += parentchildLength;
                    }
                    end  = System.currentTimeMillis();
                    System.out.println("CTUpdate3-i time: " + (end - start) + "ms");
                    break;

                } else if (type3 == 2) {
                    //读取受影响节点长度

                    ArrayList<Node> YparentAndChildren = new ArrayList<>();
                    for (Node n:accessTree2){
                        YparentAndChildren.add(n);
                    }
                    int YparentAndChildrenLength = YparentAndChildren.size();
                    //int YparentAndChildrenLength = Integer.parseInt(ukProp.getProperty("YparentAndChildren"));
//                    //read influenced root node
//                    bytes = Base64.getDecoder().decode(ctProp.getProperty("node" + accessTree.get(Y.parent).index));
//                    ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
//                    ObjectInputStream ois = new ObjectInputStream(bais);
//                    Node node = (Node) ois.readObject();
//                    //read influenced children node
//                    YparentAndChildren.add(node);
//                    for (int i = 0; i < YparentAndChildrenLength; i++) {
//                        //从文件读取节点
//                        bytes = Base64.getDecoder().decode(ctProp.getProperty("node" + accessTree.get(Y.parent).children.get(0)));
//                        bais = new ByteArrayInputStream(bytes);
//                        ois = new ObjectInputStream(bais);
//                        node = (Node) ois.readObject();
//                        //将节点存入访问树
//                        YparentAndChildren.add(node);
//                    }
                    //从ct文件中读取除去YparentAndChildren[0]的其他节点的C1_att
                    for (int i = 1; i < YparentAndChildrenLength; i++) {
                        if (YparentAndChildren.get(i).isLeaf()) {
                            //从文件读取C1_att
                            bytes = Base64.getDecoder().decode(ctProp.getProperty("C1_" + YparentAndChildren.get(i).att + uid));
                            Element C1_att_3 = bp.getG1().newElementFromBytes(bytes).getImmutable();
                            //从文件读取UK1_att
                            bytes = Base64.getDecoder().decode(ukProp.getProperty("UK1_" + YparentAndChildren.get(i).att + "_" + uid));
                            Element UK1_att_3 = bp.getG1().newElementFromBytes(bytes).getImmutable();
                            //更新C1_att
                            C1_att_3 = C1_att_3.duplicate().mul(UK1_att_3);
                            //写入C1_att覆盖原文
                            ctProp.setProperty("C1_" + YparentAndChildren.get(i).att + uid, Base64.getEncoder().encodeToString(C1_att_3.toBytes()));
                        }
                    }
                    long ttest = System.currentTimeMillis();
                    //remove Y's C1_att and C2_att
                    ctProp.remove("C1_" + Y.att + uid);
                    ctProp.remove("C2_" + Y.att + uid);
                    //let accessTree.get(Y.parent)'s gate be (t,n) to (t-1,n-1)
                    accessTree.get(Y.parent).gate[0]--;
                    accessTree.get(Y.parent).gate[1]--;

                    Yindex = Y.index;
                    //define Y's parentindex
                    int Yparentindex = accessTree.get(Y.parent).index;

                    //遍历Y父节点的子节点索引，获取Y.index的位置
                    int pos = 0;
                    boolean insertpos = false;
                    for (int i = 0; i < accessTree.get(Y.parent).children.size(); i++) {
                        if (insertpos) {
                            accessTree.get(accessTree.get(Yparentindex).children.get(i)).index--;
                            accessTree.get(Yparentindex).children.set(i, accessTree.get(Yparentindex).children.get(i) - 1);
                        }
                        if (accessTree.get(Yparentindex).children.get(i) == Yindex) {
                            pos = i;
                            insertpos = true;
                        }
                    }
                    //remove Y.index from accessTree.get(Y.parent).children
                    accessTree.get(Yparentindex).children.remove(pos);
                    accessTree.get(Yparentindex).x.remove(pos);
                    //remove Y from accessTree
                    accessTree.remove(Yindex);
                    UaccessTreeLength = accessTree.size();
                    //get accessTree.get(Y.parent).children.size()
                    YparentchildLength = accessTree.get(Yparentindex).children.size();
                    //更新后续节点的索引
                    for (int i = accessTree.get(Yparentindex).children.get(YparentchildLength - 1) + 1; i < UaccessTreeLength; ) {
                        //获取Y父节点child长度
                        int parentchildLength = accessTree.get(accessTree.get(i).parent).children.size();
                        //遍历Y父节点的子节点
                        for (int j = 0; j < parentchildLength; j++) {
                            //update children index
                            accessTree.get(accessTree.get(i).parent).children.set(j, accessTree.get(accessTree.get(i).parent).children.get(j) - 1);
                            //update node index
                            accessTree.get(i + j).index = i + j;
                        }
                        //i步长为父节点的子节点个数
                        i += parentchildLength;
                    }
                    end  = System.currentTimeMillis();
                    System.out.println("CTUpdate3-ii time: " + (end - start) + "ms");
                    break;

                } else if (type3 == 3) {
                    //从ct中读取Y_att对应的C1_att,C2_att
                    //从文件读取C1_att
                    //type3 Ynew is the bro of Y
                    bytes = Base64.getDecoder().decode(ctProp.getProperty("C1_" + Ynew.att + uid));
                    Element C1_att_3 = bp.getG1().newElementFromBytes(bytes).getImmutable();


                    //从文件读取UK1_att
                    bytes = Base64.getDecoder().decode(ukProp.getProperty("UK1_" + Ynew.att + "_" + uid));
                    Element UK1_att_3 = bp.getG1().newElementFromBytes(bytes).getImmutable();

                    //更新C1_att
                    C1_att_3 = C1_att_3.duplicate().mul(UK1_att_3);
                    //写入C1_att覆盖原文
                    ctProp.setProperty("C1_" + Ynew.att + uid, Base64.getEncoder().encodeToString(C1_att_3.toBytes()));
                    //remove Y's C1_att and C2_att
                    ctProp.remove("C1_" + Y.att + uid);
                    ctProp.remove("C2_" + Y.att + uid);

                    Yindex = Y.index;
                    //let accessTree.get(Y.parent) be leafnode
                    accessTree.get(Y.parent).children = null;
                    accessTree.get(Y.parent).gate = null;
                    accessTree.get(Y.parent).att = Ynew.att;
                    //remove Y and Ynew from accessTree
                    accessTree.remove(Yindex);
                    accessTree.remove(Ynew.index);
                    UaccessTreeLength = accessTree.size();
                    //更新后续节点的索引
                    //Y has been deleted,so Yindex is the right node of original Y
                    for (int i = Yindex; i < UaccessTreeLength; ) {
                        //获取Y父节点child长度
                        int parentchildLength = accessTree.get(accessTree.get(i).parent).children.size();
                        //遍历Y父节点的子节点
                        for (int j = 0; j < parentchildLength; j++) {
                            //update children index
                            accessTree.get(accessTree.get(i).parent).children.set(j, accessTree.get(accessTree.get(i).parent).children.get(j) - 2);
                            //update node index
                            accessTree.get(i + j).index = i + j;
                        }
                        //i步长为父节点的子节点个数
                        i += parentchildLength;
                    }
                    end  = System.currentTimeMillis();
                    System.out.println("CTUpdate3-iii time: " + (end - start) + "ms");
                    break;

                }
//                else if (type3 == 4) {
//                    //从ct中读取Y_att对应的C1_att,C2_att
//                    //从文件读取C1_att
//                    //type3 Ynew is the bro of Y
//                    bytes = Base64.getDecoder().decode(ctProp.getProperty("C1_" + Ynew.att + uid));
//                    Element C1_att_3 = bp.getG1().newElementFromBytes(bytes).getImmutable();
//
//                    Node Yparent = accessTree.get(Y.parent);
//                    Node parentbro = accessTree.get(Yparent.index+1);
//                    accessTree.remove(Yparent.index);
//                    accessTree.add(Yparent.index,accessTree2.get(0));
//                    accessTree.remove(Y.index);
//                    for(int i = 1;i<accessTree2.size();i++){
//
//                        accessTree.add(Yparent.index+i,accessTree2.get(i));
//                    }
//                }
                else {
                    System.out.println("type3不在范围内");
                }
                break;
            default:
                System.out.println("type不在范围内");
                break;


        }
//        ctProp.setProperty("accessTreeLength", Integer.toString(accessTree.size()));
//        //cover original accessTree
//        for (int i = 0; i < accessTree.size(); i++) {
//            Node node = accessTree.get(i);
//            // 3.1.对节点进行序列化
//            ObjectMapper objectMapper = new ObjectMapper();
//            String nodejson = objectMapper.writeValueAsString(node);
////            ByteArrayOutputStream baos = new ByteArrayOutputStream();
////            ObjectOutputStream oos = new ObjectOutputStream(baos);
////            oos.writeObject(node);
////            oos.flush();
////            oos.close();
//            // 3.2.将序列化后的节点写入密文Ct
//            ctProp.setProperty("node" + i, Base64.getEncoder().withoutPadding().encodeToString(nodejson.getBytes()));
//        }
//        if (accessTree.size() < accessTreeLength) {
//            //remove the rest of accessTree
//            ctProp.remove("node" + accessTree.size());
//        }
        //将ctProp写入文件
//        ctProp.store(new FileOutputStream(ctFileName), null);
        storePropToFile(ctProp, ctFileName);

    }

    //解密算法Dec，输入pairingParametersFileName，ctFileName，skFileName，useratt
    public static void Dec(Pairing bp, String PPFileName, String ctFileName, String skFileName, Map<Integer, String> useratt) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        //设置bp
//        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        //从PPFileName中导入公钥
        Properties ppProp = loadPropFromFile(PPFileName);
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("g"))).getImmutable();
        Element h = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ppProp.getProperty("h"))).getImmutable();

        //读取ctFileName文件
        Properties ctProp = loadPropFromFile(ctFileName);
        //读取C0
        Element C0 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C0"))).getImmutable();
        //读取C
        Element C = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C"))).getImmutable();


        //读取私钥文件
        Properties skProp = loadPropFromFile(skFileName);
        //从sk中读取K1,K2，K3
        Element K1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("K1"))).getImmutable();
        Element K2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("K2"))).getImmutable();
        Element K3 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("K3"))).getImmutable();

//        int accessTreeLength = accessTree.size();
//        //读取访问树
//        int accessTreeLength = Integer.parseInt(ctProp.getProperty("accessTreeLength"));
//        ArrayList<Node> accessTree = new ArrayList<Node>();
//        for (int i = 0; i < accessTreeLength; i++) {
//            //从文件读取节点
//            byte[] bytes = Base64.getDecoder().decode(ctProp.getProperty("node" + i));
//            String nodejson = new String(bytes);
//            ObjectMapper objectMapper = new ObjectMapper();
//            Node node = objectMapper.readValue(nodejson, Node.class);
//            //将节点存入访问树
//            accessTree.add(node);
//        }
        //依次从队列uidq中取出元素
        //define a ArrayList<Node> accessTreedec
        ArrayList<Node> accessTreedec = new ArrayList<>();
        for (Node node : accessTree) {
            accessTreedec.add(new Node(node));
        }
        for (Node rootnode : uidq) {
            //从rootnode中取得uid
            String uid = rootnode.uid;
            //遍历accessTree中以rootnode为根节点的子树
            boolean treeOK = AccessTree.nodeRecover(accessTreedec, accessTreedec.get(rootnode.index), useratt, g, K2, K3, skFileName, ctFileName, bp);

            if (treeOK) {
                //计算双线性对D=e(K1,C0)
                Element D = bp.pairing(K1, C0).getImmutable();
                //F=rootnode.secretshare
                Element F = accessTreedec.get(rootnode.index).secretShare.getImmutable();

                Element CF = C.mul(F).getImmutable();
                Element M = FD_MU_Scheme.vartest.get("message").getImmutable();
//                System.out.println("message:" + M);
                Element MD = D.mul(M).getImmutable();
                if (CF.equals(MD))
                    System.out.println("恢复成功");
                else {
                    System.out.println("恢复失败");
                    continue;
                }
//                恢复消息message = C*F/D
                Element message = CF.div(D);
//                Element message = C.mul(F).div(D);
                //输出消息message
                System.out.println("用户" + uid + "的消息为：" + message);
                break;
            }
            if (treeOK == false) {
                //输出不满足访问策略
                System.out.println(("用户" + uid + "的访问策略不满足，消息无法恢复"));
            }

        }
    }
    //构建递归遍历树的算法，输入访问树accessTree，根节点rootnode
//    public static Node buildTree(ArrayList<Node> accessTree, Node rootnode, Map<Integer, String> useratt,Element g, Pairing bp) throws NoSuchAlgorithmException {
//        boolean f ;
//        //判断rootnode是否为叶子节点
//        if (rootnode.children == null) {
//            //判断rootnode的属性是否在useratt中
//            if (useratt.containsKey(rootnode.att)) {
//                //判断useratt中的属性值是否与rootnode的属性值相同
//                //获取useratt中的属性值
//                String userattvalue = useratt.get(rootnode.att);
//                Element h_att = ZrhashH2(Integer.toString(rootnode.att) + userattvalue, bp).getImmutable();
//                //计算g^h_att
//                Element g_h_att = g.duplicate().powZn(h_att).getImmutable();
//                //判断e(rootnode.g_nv,g_h_att)=1，如果相等则返回rootnode，否则返回rootnode的父节点
//            } else {
//                //返回rootnode的父节点
//                return rootnode.parent;
//            }
//
//            return rootnode.parent;
//        }
//        //遍历rootnode的子节点
//        for(int i=0;i<rootnode.children.length;i++){
//            //递归遍历子节点
//            Node node = accessTree[rootnode.children[i]];
//            buildTree(accessTree,node, useratt,bp);
//        }
//
//    }

    //更新节点生成算法NodeGen，输入更新类型UType，访问树accessTree2，返回一个节点数组
    public static Node[] UNodeGen(int UType, String uid) {
        Node[] YNode = new Node[2];
        int Yindex = 0;
        //find the first leafnode from accessTree
        for (Node node : accessTree) {
            if (node.uid != null && node.uid.equals(uid) && node.children == null) {
                YNode[0] = node;
                Yindex = node.index;
                break;
            }
        }
        //判断更新类型UType
        if (UType == 1) {
            //随机生成一个节点
            Node Ynew = new Node(YNode[0]);
            //随机选择属性
            int randomInt = (int) (Math.random() * 1000);
            Ynew.att = randomInt;
            //将节点加入YNode
            YNode[1] = Ynew;
        }
        if (UType == 2) {
            //随机生成一个节点
            Node Ynew = new Node(YNode[0]);
            //秘密值分片横坐标为最后一个兄弟节点横坐标加一
            int lastchildnodeindex = accessTree.get(YNode[0].parent).children.get(accessTree.get(YNode[0].parent).children.size() - 1);
            Ynew.xindex = accessTree.get(lastchildnodeindex).xindex + 1;
            Ynew.index = accessTree.get(lastchildnodeindex).index + 1;
            //随机选择属性
            int randomInt = (int) (Math.random() * 1000);
            Ynew.att = randomInt;
            //将节点加入YNode
            YNode[1] = Ynew;
        }
        if (UType == 3) {
            //定位兄弟节点
//            boolean f = false;
            Node Ybro = new Node(accessTree.get(Yindex + 1));
//            Node Ybro = new Node();
//            for(int i=0;i<accessTree2.get(YNode[0].parent).children.size();i++){
//                if(accessTree2.get(YNode[0].parent).children.get(i)==Yindex){
//                    f = true;
//                    continue;
//                }
//                if (f){
//                    Ybro = accessTree2.get(accessTree2.get(YNode[0].parent).children.get(i));
//                    break;
//                }
//            }
            //将节点加入YNode
            YNode[1] = Ybro;
        }
        return YNode;
    }

    //遍历accessTree中以rootnode为根节点的子树，放入YparentAndChildren中返回
    public static void traverceTree(Node rootnode, ArrayList<Node> YparentAndChildren) {
        //判断rootnode是否为叶子节点
        if (rootnode.children == null) {
            //将rootnode加入YparentAndChildren
            YparentAndChildren.add(rootnode);
            return;
        } else {
            //遍历rootnode的子节点
            for (int i = 0; i < rootnode.children.size(); i++) {
                //将rootnode加入YparentAndChildren
                YparentAndChildren.add(rootnode);
                //递归遍历子节点
                Node node = accessTree.get(rootnode.children.get(i));
                traverceTree(node, YparentAndChildren);
            }
        }

    }

    //构建生成随机属性名和属性值的方法，通过输入属性名个数，生成属性名和属性值并以键值对集合返回
    public static Map<Integer, String> buildRandomAttributes(int k) {
        Map<Integer, String> attributes = new HashMap<>();
        int leafnodenum = (int) Math.pow(3, k - 1);
        for (int i = 0; i < leafnodenum; i++) {
            String uuid = UUID.randomUUID().toString();
            //转换uid为integer
            int uid = uuid.hashCode();
            attributes.put(uid, "value" + uuid);
        }
        return attributes;
    }


    public static Element GhashH1(String s, Pairing bp) throws NoSuchAlgorithmException {
        byte[] idHash = sha1(s);
        Element G1Element = bp.getG1().newElementFromHash(idHash, 0, idHash.length);
        return G1Element;

    }

    public static Element ZrhashH2(String s, Pairing bp) throws NoSuchAlgorithmException {
        byte[] idHash = sha1(s);
        Element zrElement = bp.getZr().newElementFromHash(idHash, 0, idHash.length);
        return zrElement;

    }

    //构造将群G元素映射为Zr元素的哈希函数
    public static Element GhashH3(Element g, Pairing bp) throws NoSuchAlgorithmException {
        byte[] idHash = sha1(g.toString());
        Element zrElement = bp.getZr().newElementFromHash(idHash, 0, idHash.length);
        return zrElement;

    }

    public static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static void storePropToFile(Properties prop, String fileName) {
        try (FileOutputStream out = new FileOutputStream(fileName)) {
            prop.store(out, null);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)) {
            prop.load(in);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }

    public static void basicTest() throws Exception {
        //define the depth k of accessTree
        int depth = 3;
        int userNum = 10;
        int UType = 2;
        //生成用属性名和属性值构建的属性集合，属性个数为5
        Map<Integer, String> useratt = buildRandomAttributes(depth);

        System.out.println("加密/签名属性个数：" + useratt.size());
        //define a array dataownerAttList from useratt's key
        int[] dataownerAttList = new int[useratt.size()];
        int i = 0;
        for (Integer key : useratt.keySet()) {
            dataownerAttList[i] = key;
            i++;
        }
        //output the dataownerAttList
        System.out.println("用户属性列表：" + Arrays.toString(dataownerAttList));
        //define a user id
        String uid = "user0";
        accessTree = AutoGenTree.tree(dataownerAttList, depth, uid);
        uidq.add(new Node(accessTree.get(0)));
        //计算层高为k的满三叉树节点总数
        int nodenum = (int) Math.pow(3, depth) - 1;


        String dir = "data/";
        String pairingParametersFileName = "F:/Program Files/Java/jpbc-2.0.0/params/curves/a.properties";
        String PPFileName = dir + "PP.properties";
        String mskFileName = dir + "msk.properties";
        String skFileName = dir + "sk.properties";
        String uskFileName = dir + "usk.properties";
        String ctFileName = dir + "ct.properties";
        String ukFileName = dir + "uk.properties";
        String accessTreeFileName = dir + "ac.properties";
//        String fileName = dir + "message1.txt";
        String uctFileName = dir + "uct.properties";


        //randomly choose a message to encrypt from G1
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Element test1 = ZrhashH2("test", bp);
        Element test2 = ZrhashH2("test", bp);

        Element message = bp.getGT().newRandomElement().getImmutable();
        System.out.println("明文消息:" + message);
        vartest.put("message", message);

        System.out.println("开始加密");
        //setup
        long start = System.currentTimeMillis();
        setup(bp, PPFileName, mskFileName);
        long end = System.currentTimeMillis();
        System.out.println("setup successful");
        System.out.println("setup time:" + (end - start) + "ms");
        //KeyGen
        start = System.currentTimeMillis();
        KeyGen(bp, PPFileName, mskFileName, useratt, uid, skFileName);
        end = System.currentTimeMillis();
        System.out.println("KeyGen time:" + (end - start) + "ms");
        System.out.println("KeyGen successful");

        Map<Integer, String> unsatisfyuseratt = buildRandomAttributes(depth);
        KeyGen(bp, PPFileName, mskFileName, unsatisfyuseratt, "unsat_user", uskFileName);

        //Enc
        for (Node node : accessTree) {
            encaccessTree.add(new Node(node));
        }
        start = System.currentTimeMillis();
        Enc(bp, PPFileName, message, useratt, uid, ctFileName);
        end = System.currentTimeMillis();
        accessTree = new ArrayList<>();
        for (Node node : encaccessTree) {
            accessTree.add(new Node(node));
        }
        System.out.println("Enc successful");
        System.out.println("Enc time:" + (end - start) + "ms");
        //Dec
        start = System.currentTimeMillis();
        Dec(bp, PPFileName, ctFileName, skFileName, useratt);
        end = System.currentTimeMillis();
        System.out.println("Dec successful");
        System.out.println("Dec time:" + (end - start) + "ms");

        //multiuser dedup--------------------------------------------------------------------

        Map<Integer, String> userattdup = new HashMap<>();
        for (int currentnum = 1; currentnum < userNum; currentnum++) {
            //define the depth k of accessTree
            int kk = 3;
            //生成用属性名和属性值构建的属性集合，属性个数为5
            userattdup = buildRandomAttributes(depth);
//            System.out.println("加密/签名属性个数：" + useratt.size());
            //define a array dataownerAttList from useratt's key
            int[] dataownerAttListdup = new int[userattdup.size()];
            int ii = 0;
            for (Integer key : userattdup.keySet()) {
                dataownerAttListdup[ii] = key;
                ii++;
            }
            //output the dataownerAttList
//            System.out.println("用户属性名列表：" + Arrays.toString(dataownerAttListdup));
            //define a user id
            uid = "user" + currentnum;
            accessTree2 = new ArrayList<>();
            accessTree2 = AutoGenTree.tree(dataownerAttListdup, depth, uid);
            //KeyGen
//            start = System.currentTimeMillis();
//            KeyGen(bp, PPFileName, mskFileName, userattdup,uid, uskFileName);
//            end = System.currentTimeMillis();
//            System.out.println("KeyGen successful");
//            System.out.println("KeyGen time:" + (end - start) + "ms");
            //Enc
            encaccessTree = new ArrayList<>();
            for (Node node : accessTree2)
                encaccessTree.add(new Node(node));
            Enc(bp, PPFileName, message, userattdup, uid, uctFileName);
            accessTree2 = new ArrayList<>();
            for (Node node : encaccessTree)
                accessTree2.add(new Node(node));
            //Dup
//            System.out.println("去重检测，访问树融合：-----------------------------------------------------------------------------------");
            start = System.currentTimeMillis();
            Dup(bp, ctFileName, uctFileName, uid);
            end = System.currentTimeMillis();
            System.out.println("Dup successful");
            System.out.println("Dup time "+currentnum+":" + (end - start) + "ms");
        }
        //test dupdec
        int count = 0;
        for (Node n : accessTree) {
            if (n.isLeaf())
                count++;
        }
        System.out.println("去重后访问树叶子节点个数：" + count);

        System.out.println("(多用户)开始解密：-----------------------------------------------------------------------------------");
        start = System.currentTimeMillis();
//        Dec(bp, PPFileName, ctFileName, uskFileName, unsatisfyuseratt);
        Dec(bp, PPFileName, ctFileName, skFileName, useratt);
        end = System.currentTimeMillis();
        System.out.println("Dec successful");
        System.out.println("Dec time:" + (end - start) + "ms");

//        //define a vector UYY that the length is 2
//        Node[] UYY = UNodeGen(UType, uid);
//        Node Y = new Node(UYY[0]);
//        Node Ynew = new Node(UYY[1]);
////        accessTree.get(Y.parent).gate[0]=3;
//        String Ynewvalue = "value" + Ynew.att;
//        //UKgen
//        start = System.currentTimeMillis();
//        UKeyGen(bp, PPFileName, ctFileName, uid, UType, Y, Ynew, Ynewvalue, ukFileName);
//        end = System.currentTimeMillis();
//        System.out.println("UKgen successful");
//        System.out.println("UKgen time:" + (end - start) + "ms");
//        //CTUpadate
//        start = System.currentTimeMillis();
//        CTUpdate(bp, PPFileName, ctFileName, Y, Ynew, uid, ukFileName);
//        end = System.currentTimeMillis();
//        System.out.println("CTUpdate successful");
//        System.out.println("CTUpdate time:" + (end - start) + "ms");


//        setup(bp, PPFileName, mskFileName);

    }

    public static void main(String[] args) throws Exception {

        basicTest();
    }
}
