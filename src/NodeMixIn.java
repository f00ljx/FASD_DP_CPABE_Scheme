import com.fasterxml.jackson.annotation.JsonIgnore;
import it.unisa.dia.gas.jpbc.Element;
public class NodeMixIn {
    @JsonIgnore
    public Element g_nv;
    @JsonIgnore
    public Element[] coef;
    @JsonIgnore
    public Element secretShare;
}
