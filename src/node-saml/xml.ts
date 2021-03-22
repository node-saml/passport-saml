import * as xmlCrypto from "xml-crypto";

type SelectedValue = string | number | boolean | Node;

const selectXPath = <T extends SelectedValue>(
  guard: (values: SelectedValue[]) => values is T[],
  node: Node,
  xpath: string
): T[] => {
  const result = xmlCrypto.xpath(node, xpath);
  if (!guard(result)) {
    throw new Error("invalid xpath return type");
  }
  return result;
};

const attributesXPathTypeGuard = (values: SelectedValue[]): values is Attr[] => {
  return values.every((value) => {
    if (typeof value != "object") {
      return false;
    }
    return typeof value.nodeType === "number" && value.nodeType === value.ATTRIBUTE_NODE;
  });
};

const elementsXPathTypeGuard = (values: SelectedValue[]): values is Element[] => {
  return values.every((value) => {
    if (typeof value != "object") {
      return false;
    }
    return typeof value.nodeType === "number" && value.nodeType === value.ELEMENT_NODE;
  });
};

export const xpath = {
  selectAttributes: (node: Node, xpath: string): Attr[] =>
    selectXPath(attributesXPathTypeGuard, node, xpath),
  selectElements: (node: Node, xpath: string): Element[] =>
    selectXPath(elementsXPathTypeGuard, node, xpath),
};
