
namespace FiveRxLinkSecurityLib.Global
{
  /// <remarks/>
  [System.CodeDom.Compiler.GeneratedCodeAttribute("svcutil", "4.0.30319.17929")]
  [System.SerializableAttribute()]
  [System.Diagnostics.DebuggerStepThroughAttribute()]
  [System.ComponentModel.DesignerCategoryAttribute("code")]
  [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://fiverx.de/security/types")]
  public partial class einParameterRequestMsg
  {

    private string rzeEingabeDatenField;

    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form = System.Xml.Schema.XmlSchemaForm.Unqualified, Order = 0)]
    public string rzeEingabeDaten
    {
      get
      {
        return this.rzeEingabeDatenField;
      }
      set
      {
        this.rzeEingabeDatenField = value;
      }
    }
  }

  /// <remarks/>
  [System.CodeDom.Compiler.GeneratedCodeAttribute("svcutil", "4.0.30319.17929")]
  [System.SerializableAttribute()]
  [System.Diagnostics.DebuggerStepThroughAttribute()]
  [System.ComponentModel.DesignerCategoryAttribute("code")]
  [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://fiverx.de/security/types")]
  public partial class zweiParameterRequestMsg
  {

    private string rzeEingabeDatenField;

    private string rzeLadeRzSecurityVersionField;

    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form = System.Xml.Schema.XmlSchemaForm.Unqualified, Order = 0)]
    public string rzeEingabeDaten
    {
      get
      {
        return this.rzeEingabeDatenField;
      }
      set
      {
        this.rzeEingabeDatenField = value;
      }
    }

    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form = System.Xml.Schema.XmlSchemaForm.Unqualified, Order = 1)]
    public string rzeLadeRzSecurityVersion
    {
      get
      {
        return this.rzeLadeRzSecurityVersionField;
      }
      set
      {
        this.rzeLadeRzSecurityVersionField = value;
      }
    }
  }

  /// <remarks/>
  [System.CodeDom.Compiler.GeneratedCodeAttribute("svcutil", "4.0.30319.17929")]
  [System.SerializableAttribute()]
  [System.Diagnostics.DebuggerStepThroughAttribute()]
  [System.ComponentModel.DesignerCategoryAttribute("code")]
  [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://fiverx.de/security/types")]
  public partial class genericResponseMsg
  {

    private string rzeAusgabeDatenField;

    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form = System.Xml.Schema.XmlSchemaForm.Unqualified, Order = 0)]
    public string rzeAusgabeDaten
    {
      get
      {
        return this.rzeAusgabeDatenField;
      }
      set
      {
        this.rzeAusgabeDatenField = value;
      }
    }
  }

  [System.Diagnostics.DebuggerStepThroughAttribute()]
  [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
  [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
  [System.ServiceModel.MessageContractAttribute(IsWrapped = false)]
  public partial class ladeRzSecurityVersionRequest
  {

    [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "http://fiverx.de/security/types", Order = 0)]
    public einParameterRequestMsg ladeRzSecurityVersionRequestMsg;

    public ladeRzSecurityVersionRequest()
    {
    }

    public ladeRzSecurityVersionRequest(einParameterRequestMsg ladeRzSecurityVersionRequestMsg)
    {
      this.ladeRzSecurityVersionRequestMsg = ladeRzSecurityVersionRequestMsg;
    }
  }

  [System.Diagnostics.DebuggerStepThroughAttribute()]
  [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
  [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
  [System.ServiceModel.MessageContractAttribute(IsWrapped = false)]
  public partial class ladeRzSecurityVersionResponse
  {

    [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "http://fiverx.de/security/types", Order = 0)]
    public genericResponseMsg ladeRzSecurityVersionResponseMsg;

    public ladeRzSecurityVersionResponse()
    {
    }

    public ladeRzSecurityVersionResponse(genericResponseMsg ladeRzSecurityVersionResponseMsg)
    {
      this.ladeRzSecurityVersionResponseMsg = ladeRzSecurityVersionResponseMsg;
    }
  }

  [System.Diagnostics.DebuggerStepThroughAttribute()]
  [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
  [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
  [System.ServiceModel.MessageContractAttribute(IsWrapped = false)]
  public partial class ladeRzZertifikatRequest
  {

    [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "http://fiverx.de/security/types", Order = 0)]
    public zweiParameterRequestMsg ladeRzZertifikatRequestMsg;

    public ladeRzZertifikatRequest()
    {
    }

    public ladeRzZertifikatRequest(zweiParameterRequestMsg ladeRzZertifikatRequestMsg)
    {
      this.ladeRzZertifikatRequestMsg = ladeRzZertifikatRequestMsg;
    }
  }

  [System.Diagnostics.DebuggerStepThroughAttribute()]
  [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
  [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
  [System.ServiceModel.MessageContractAttribute(IsWrapped = false)]
  public partial class ladeRzZertifikatResponse
  {

    [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "http://fiverx.de/security/types", Order = 0)]
    public genericResponseMsg ladeRzZertifikatResponseMsg;

    public ladeRzZertifikatResponse()
    {
    }

    public ladeRzZertifikatResponse(genericResponseMsg ladeRzZertifikatResponseMsg)
    {
      this.ladeRzZertifikatResponseMsg = ladeRzZertifikatResponseMsg;
    }
  }

  [System.Diagnostics.DebuggerStepThroughAttribute()]
  [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
  [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
  [System.ServiceModel.MessageContractAttribute(IsWrapped = false)]
  public partial class ladeRzSicherheitsmerkmaleRequest
  {

    [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "http://fiverx.de/security/types", Order = 0)]
    public zweiParameterRequestMsg ladeRzSicherheitsmerkmaleRequestMsg;

    public ladeRzSicherheitsmerkmaleRequest()
    {
    }

    public ladeRzSicherheitsmerkmaleRequest(zweiParameterRequestMsg ladeRzSicherheitsmerkmaleRequestMsg)
    {
      this.ladeRzSicherheitsmerkmaleRequestMsg = ladeRzSicherheitsmerkmaleRequestMsg;
    }
  }

  [System.Diagnostics.DebuggerStepThroughAttribute()]
  [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
  [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
  [System.ServiceModel.MessageContractAttribute(IsWrapped = false)]
  public partial class ladeRzSicherheitsmerkmaleResponse
  {

    [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "http://fiverx.de/security/types", Order = 0)]
    public genericResponseMsg ladeRzSicherheitsmerkmaleResponseMsg;

    public ladeRzSicherheitsmerkmaleResponse()
    {
    }

    public ladeRzSicherheitsmerkmaleResponse(genericResponseMsg ladeRzSicherheitsmerkmaleResponseMsg)
    {
      this.ladeRzSicherheitsmerkmaleResponseMsg = ladeRzSicherheitsmerkmaleResponseMsg;
    }
  }

  [System.Diagnostics.DebuggerStepThroughAttribute()]
  [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
  [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
  [System.ServiceModel.MessageContractAttribute(IsWrapped = false)]
  public partial class aktiviereApothekenZugangRequest
  {

    [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "http://fiverx.de/security/types", Order = 0)]
    public zweiParameterRequestMsg aktiviereApothekenZugangRequestMsg;

    public aktiviereApothekenZugangRequest()
    {
    }

    public aktiviereApothekenZugangRequest(zweiParameterRequestMsg aktiviereApothekenZugangRequestMsg)
    {
      this.aktiviereApothekenZugangRequestMsg = aktiviereApothekenZugangRequestMsg;
    }
  }

  [System.Diagnostics.DebuggerStepThroughAttribute()]
  [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
  [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
  [System.ServiceModel.MessageContractAttribute(IsWrapped = false)]
  public partial class aktiviereApothekenZugangResponse
  {

    [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "http://fiverx.de/security/types", Order = 0)]
    public genericResponseMsg aktiviereApothekenZugangResponseMsg;

    public aktiviereApothekenZugangResponse()
    {
    }

    public aktiviereApothekenZugangResponse(genericResponseMsg aktiviereApothekenZugangResponseMsg)
    {
      this.aktiviereApothekenZugangResponseMsg = aktiviereApothekenZugangResponseMsg;
    }
  }

  [System.Diagnostics.DebuggerStepThroughAttribute()]
  [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
  [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
  [System.ServiceModel.MessageContractAttribute(IsWrapped = false)]
  public partial class verlaengereApothekenZugangRequest
  {

    [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "http://fiverx.de/security/types", Order = 0)]
    public zweiParameterRequestMsg verlaengereApothekenZugangRequestMsg;

    public verlaengereApothekenZugangRequest()
    {
    }

    public verlaengereApothekenZugangRequest(zweiParameterRequestMsg verlaengereApothekenZugangRequestMsg)
    {
      this.verlaengereApothekenZugangRequestMsg = verlaengereApothekenZugangRequestMsg;
    }
  }

  [System.Diagnostics.DebuggerStepThroughAttribute()]
  [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
  [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
  [System.ServiceModel.MessageContractAttribute(IsWrapped = false)]
  public partial class verlaengereApothekenZugangResponse
  {

    [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "http://fiverx.de/security/types", Order = 0)]
    public genericResponseMsg verlaengereApothekenZugangResponseMsg;

    public verlaengereApothekenZugangResponse()
    {
    }

    public verlaengereApothekenZugangResponse(genericResponseMsg verlaengereApothekenZugangResponseMsg)
    {
      this.verlaengereApothekenZugangResponseMsg = verlaengereApothekenZugangResponseMsg;
    }
  }

  [System.Diagnostics.DebuggerStepThroughAttribute()]
  [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
  [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
  [System.ServiceModel.MessageContractAttribute(IsWrapped = false)]
  public partial class verarbeiteAuftragRequest
  {

    [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "http://fiverx.de/security/types", Order = 0)]
    public zweiParameterRequestMsg verarbeiteAuftragRequestMsg;

    public verarbeiteAuftragRequest()
    {
    }

    public verarbeiteAuftragRequest(zweiParameterRequestMsg verarbeiteAuftragRequestMsg)
    {
      this.verarbeiteAuftragRequestMsg = verarbeiteAuftragRequestMsg;
    }
  }

  [System.Diagnostics.DebuggerStepThroughAttribute()]
  [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
  [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
  [System.ServiceModel.MessageContractAttribute(IsWrapped = false)]
  public partial class verarbeiteAuftragResponse
  {

    [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "http://fiverx.de/security/types", Order = 0)]
    public genericResponseMsg verarbeiteAuftragResponseMsg;

    public verarbeiteAuftragResponse()
    {
    }

    public verarbeiteAuftragResponse(genericResponseMsg verarbeiteAuftragResponseMsg)
    {
      this.verarbeiteAuftragResponseMsg = verarbeiteAuftragResponseMsg;
    }
  }
}
